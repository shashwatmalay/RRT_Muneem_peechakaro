require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");
const { google } = require("googleapis");
const cron = require("node-cron");
const jwt = require("jsonwebtoken");
const moment = require("moment-timezone");
const pLimit = require("p-limit").default;

const prisma = new PrismaClient();
const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;
const CLIENT_ID = process.env.CLIENT_ID || "";
const CLIENT_SECRET = process.env.CLIENT_SECRET || "";
const REDIRECT_URI =
  process.env.REDIRECT_URI || "http://localhost:5000/oauth2callback";
const CRON_INTERVAL = process.env.CRON_INTERVAL || 2; // minutes
const PARALLEL_LIMIT = parseInt(process.env.PARALLEL_LIMIT || "8", 10); // default 8
const PER_MESSAGE_LIMIT = parseInt(process.env.PER_MESSAGE_LIMIT || "5", 10); // per-candidate message fetch concurrency

let isCronRunning = false;
const deletedCandidates = new Set();

// -------------------- HELPERS --------------------
function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

function detectMailSource(fromEmail) {
  if (!fromEmail || fromEmail === "Unknown") return "company";
  const email = fromEmail.toLowerCase();
  const platforms = [
    "linkedin.com",
    "indeed.com",
    "glassdoor.com",
    "simplyhired.com",
    "dice.com",
    "monster.com",
    "careerbuilder.com",
    "apexsystems.com",
    "ziprecruiter.com",
    "randstad.com",
    "roberthalf.com",
    "brooksource.com",
    "insightglobal.com",
    "teksystems.com",
    "kforce.com",
    "levels.fyi",
    "talenty.io",
    "jobright.com",
    "swooped.com",
    "simplify.com",
    "builtin.com",
    "workable.com",
  ];
  return platforms.some((d) => email.includes(d)) ? "platform" : "company";
}

function extractAllTextFromPayload(payload) {
  let acc = "";
  function walk(part) {
    if (!part) return;
    if (part.body && part.body.data) {
      try {
        acc += Buffer.from(part.body.data, "base64").toString("utf-8") + " ";
      } catch (e) {}
    }
    if (part.parts && Array.isArray(part.parts)) part.parts.forEach(walk);
  }
  walk(payload);
  acc = acc.replace(/<[^>]+>/g, " ");
  acc = acc.replace(/&nbsp;|&amp;|&lt;|&gt;|&quot;|&#39;/g, " ");
  return acc;
}

// Recompute exact counts from messages table and write into candidate row (atomic-ish)
async function updateCandidateCounts(candidateId) {
  // Count all messages for candidate
  const total = await prisma.message.count({ where: { candidateId } });
  // Count platform messages
  // We can't do detectMailSource inside DB, so fetch counts grouped by source in JS:
  const msgs = await prisma.message.findMany({
    where: { candidateId },
    select: { from: true },
  });
  let platformCount = 0;
  for (const m of msgs)
    if (detectMailSource(m.from) === "platform") platformCount++;
  const companyCount = total - platformCount;

  await prisma.candidate.update({
    where: { id: candidateId },
    data: { count: total, platformCount, companyCount },
  });
  log(
    `Counts updated for candidate ${candidateId}: total=${total}, platform=${platformCount}, company=${companyCount}`
  );
}

// Get today's counts grouped by candidate (EST) — used for GET /candidates dailyCount
async function getTodayCountsGrouped() {
  const startEST = moment.tz("America/New_York").startOf("day").utc().toDate();
  const endEST = moment.tz("America/New_York").endOf("day").utc().toDate();

  // Group by candidateId: prisma.groupBy
  const groups = await prisma.message.groupBy({
    by: ["candidateId"],
    where: { createdAt: { gte: startEST, lte: endEST } },
    _count: { id: true },
  });

  const map = {};
  for (const g of groups) map[g.candidateId] = g._count.id;
  return map;
}

// -------------------- ROUTES --------------------
app.get("/", (req, res) => res.send({ status: "ok" }));

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const admin = await prisma.admin.findFirst();
    if (!admin)
      return res
        .status(404)
        .json({
          error:
            "No admin found. Please set credentials first via Forgot Password.",
        });
    if (admin.username !== username || admin.password !== password)
      return res.status(401).json({ error: "Invalid username or password" });
    const token = jwt.sign(
      { username },
      process.env.JWT_SECRET || "supersecretkey",
      { expiresIn: "1h" }
    );
    res.json({ token, username });
  } catch (err) {
    log("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

app.post("/forgot-password-question", async (req, res) => {
  try {
    let admin = await prisma.admin.findFirst();
    if (!admin) {
      admin = await prisma.admin.create({
        data: {
          username: "",
          password: "",
          question: "What happened on your birthday?",
          answer: "default",
        },
      });
    }
    res.json({ question: admin.question });
  } catch (err) {
    log("Forgot question error:", err);
    res.status(500).json({ error: "Failed to get question" });
  }
});

app.post("/verify-answer", async (req, res) => {
  const { answer } = req.body;
  try {
    const admin = await prisma.admin.findFirst();
    if (!admin) return res.status(404).json({ error: "No admin found" });
    if (
      (answer || "").trim().toLowerCase() !==
      (admin.answer || "").trim().toLowerCase()
    )
      return res.status(401).json({ error: "Incorrect answer" });
    res.json({ success: true });
  } catch (err) {
    log("Verify answer error:", err);
    res.status(500).json({ error: "Verification failed" });
  }
});

app.post("/reset-credentials", async (req, res) => {
  const { newUsername, newPassword, confirmPassword } = req.body;
  if (newPassword !== confirmPassword)
    return res.status(400).json({ error: "Passwords do not match" });
  try {
    let admin = await prisma.admin.findFirst();
    if (!admin) {
      admin = await prisma.admin.create({
        data: {
          username: newUsername,
          password: newPassword,
          question: "What happened on your birthday?",
          answer: "default",
        },
      });
    } else {
      await prisma.admin.update({
        where: { id: admin.id },
        data: { username: newUsername, password: newPassword },
      });
    }
    res.json({ success: true, message: "Credentials updated successfully" });
  } catch (err) {
    log("Reset credentials error:", err);
    res.status(500).json({ error: "Failed to update credentials" });
  }
});

app.post("/candidates", async (req, res) => {
  const { name, email } = req.body;
  if (!name || !email)
    return res.status(400).json({ error: "name and email required" });
  try {
    const newCandidate = await prisma.candidate.create({
      data: {
        name,
        email: email.toLowerCase().trim(),
        count: 0,
        platformCount: 0,
        companyCount: 0,
      },
    });
    res.status(201).json(newCandidate);
  } catch (err) {
    log("Error adding candidate:", err);
    if (err.code === "P2002")
      return res
        .status(409)
        .json({ error: "Candidate with this email already exists" });
    res.status(500).json({ error: "Failed to add candidate" });
  }
});

app.delete("/candidates/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    await prisma.$transaction([
      prisma.message.deleteMany({ where: { candidateId: id } }),
      prisma.candidate.delete({ where: { id } }),
    ]);
    deletedCandidates.add(id);
    res.json({ success: true, message: "Candidate deleted" });
  } catch (err) {
    log("Delete candidate error:", err);
    res.status(500).json({ error: "Failed to delete candidate" });
  }
});

// OAuth routes
app.get("/auth/:candidateId", (req, res) => {
  const { candidateId } = req.params;
  const oAuth2Client = new google.auth.OAuth2(
    CLIENT_ID,
    CLIENT_SECRET,
    REDIRECT_URI
  );
  const authUrl = oAuth2Client.generateAuthUrl({
    access_type: "offline",
    scope: ["https://www.googleapis.com/auth/gmail.readonly"],
    state: candidateId,
    prompt: "consent",
  });
  res.redirect(authUrl);
});

app.get("/oauth2callback", async (req, res) => {
  try {
    const code = req.query.code;
    const candidateId = req.query.state;
    if (!code || !candidateId)
      return res.status(400).send("Missing code or state.");
    const oAuth2Client = new google.auth.OAuth2(
      CLIENT_ID,
      CLIENT_SECRET,
      REDIRECT_URI
    );
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);
    const profile = await google
      .gmail({ version: "v1", auth: oAuth2Client })
      .users.getProfile({ userId: "me" });
    const googleEmail = profile?.data?.emailAddress || "";
    const candidate = await prisma.candidate.findUnique({
      where: { id: parseInt(candidateId) },
    });
    if (!candidate) return res.status(404).send("Candidate not found.");
    if (
      candidate.email.toLowerCase().trim() !== googleEmail.toLowerCase().trim()
    )
      return res
        .status(400)
        .send(
          `Authorized Google account (${googleEmail}) does not match candidate email (${candidate.email}).`
        );
    await prisma.candidate.update({
      where: { id: candidate.id },
      data: {
        accessToken: tokens.access_token || null,
        refreshToken: tokens.refresh_token || null,
      },
    });
    res.send("✅ OAuth Success — account verified and tokens saved.");
  } catch (err) {
    log("OAuth callback error:", err);
    res.status(500).send("OAuth failed");
  }
});

// -------------------- MAIL CHECK & PROCESS --------------------
async function checkMailsAndUpdateCount() {
  if (isCronRunning) {
    log("Cron already running — skipping this run.");
    return;
  }
  isCronRunning = true;
  log("Cron started.");

  const subjects = [
    "Thank you for applying",
    "Thank you for applying!",
    "Thanks for applying",
    "We received your",
    "Application Received",
    "Your application for the position",
    "Your recent application for the position",
    "we've received",
    "We have successfully received your application",
    "Submitted:",
    "we have received",
    "submitted",
    "your application was sent",
    "Submission",
    "Thank you for your application",
    "Thank you for your application!",
    "Thank you for the application",
    "Application was received",
    "Thanks for your application",
    "Thanks for completing your application",
    "has been received",
    "Indeed Application:",
    "We received your application",
    "we received your job application",
    "we received job application",
    "Application Acknowledgement",
    "Thank you for your interest",
    "Thank you for your job application",
    "your resume was received",
    "Thank you for submitting your application",
  ];
  const query = "subject:(" + subjects.map((s) => `"${s}"`).join(" OR ") + ")";
  const maxFetch = 100000;
  const rejectRegex =
    /(not|won't|unable|unfortunate|unfortunately| other candidates|with other candidates|regret to inform|declined|position has been filled|no longer under consideration|another candidate)/i;

  try {
    const candidates = await prisma.candidate.findMany({
      where: { refreshToken: { not: null } },
    });
    if (!candidates || candidates.length === 0) {
      log("No candidates with refreshToken found.");
      return;
    }

    const limit = pLimit(PARALLEL_LIMIT);

    await Promise.all(
      candidates.map((candidate) =>
        limit(async () => {
          if (deletedCandidates.has(candidate.id)) return;

          // re-check candidate existence
          const freshCandidate = await prisma.candidate.findUnique({
            where: { id: candidate.id },
          });
          if (!freshCandidate) {
            deletedCandidates.add(candidate.id);
            return;
          }
          if (!freshCandidate.accessToken && !freshCandidate.refreshToken)
            return;

          try {
            const client = new google.auth.OAuth2(
              CLIENT_ID,
              CLIENT_SECRET,
              REDIRECT_URI
            );
            client.setCredentials({
              access_token: freshCandidate.accessToken,
              refresh_token: freshCandidate.refreshToken,
            });

            // ✅ NEW: Safe refresh handling
            try {
              // Try explicit refresh using refresh token (more reliable than only getAccessToken)
              const refreshed = await client.refreshAccessToken();
              const newAccess = refreshed?.credentials?.access_token;
              if (newAccess) {
                if (!freshCandidate.accessToken || freshCandidate.accessToken !== newAccess) {
                  await prisma.candidate.update({
                    where: { id: freshCandidate.id },
                    data: { accessToken: newAccess },
                  });
                }
                client.setCredentials({
                  access_token: newAccess,
                  refresh_token: freshCandidate.refreshToken,
                });
                log(`✅ Refreshed access token for ${freshCandidate.email}`);
              }
            } catch (e) {
              // If refresh token invalid/revoked - clear tokens and skip this candidate
              const msg = (e && e.message) || "";
              if (msg.includes("invalid_grant") || msg.includes("invalid_grant")) {
                log(`⚠️ Refresh token invalid for ${freshCandidate.email}. Clearing tokens.`);
                await prisma.candidate.update({
                  where: { id: freshCandidate.id },
                  data: { accessToken: null, refreshToken: null },
                });
                return;
              } else {
                log(`⚠️ Access token refresh failed for ${freshCandidate.email}:`, msg || e);
                // continue with whatever credentials are present (may work if accessToken still valid)
              }
            }

            const gmail = google.gmail({ version: "v1", auth: client });

            // List message ids matching query (paginate)
            let allMessages = [];
            let nextPageToken = null;
            do {
              const listRes = await gmail.users.messages.list({
                userId: "me",
                q: query,
                labelIds: ["INBOX"],
                maxResults: 100,
                pageToken: nextPageToken,
              });
              if (listRes.data?.messages)
                allMessages = allMessages.concat(listRes.data.messages);
              nextPageToken = listRes.data?.nextPageToken;
              if (allMessages.length >= maxFetch) break;
            } while (nextPageToken);

            if (!allMessages || allMessages.length === 0) return;
            allMessages = allMessages.slice(0, maxFetch);

            // Find which message ids are new
            const ids = allMessages.map((m) => m.id);
            const existing = await prisma.message.findMany({
              where: { id: { in: ids } },
              select: { id: true },
            });
            const existingIds = new Set(existing.map((e) => e.id));
            const newIds = ids.filter((id) => !existingIds.has(id));
            if (newIds.length === 0) return;

            // Fetch new messages details in parallel (limited)
            const perMsgLimit = pLimit(PER_MESSAGE_LIMIT);
            const fetchedMsgs = await Promise.all(
              newIds.map((mid) =>
                perMsgLimit(async () => {
                  try {
                    const msgRes = await gmail.users.messages.get({
                      userId: "me",
                      id: mid,
                    });
                    const msg = msgRes.data;
                    const msgTime = parseInt(
                      msg.internalDate || `${Date.now()}`
                    );
                    const msgDateUTC = new Date(msgTime);

                    let fromHeader = "Unknown",
                      subject = "",
                      bodyRaw = "";
                    if (msg.payload?.headers) {
                      for (const h of msg.payload.headers) {
                        if (h.name.toLowerCase() === "from")
                          fromHeader = h.value;
                        if (h.name.toLowerCase() === "subject")
                          subject = h.value || "";
                      }
                    }
                    if (msg.payload)
                      bodyRaw = extractAllTextFromPayload(msg.payload);
                    if (!bodyRaw || bodyRaw.trim().length < 10) {
                      try {
                        const rawMsg = await gmail.users.messages.get({
                          userId: "me",
                          id: mid,
                          format: "raw",
                        });
                        bodyRaw = Buffer.from(
                          rawMsg.data.raw,
                          "base64"
                        ).toString("utf-8");
                      } catch (e) {}
                    }

                    const body = (bodyRaw || "")
                      .replace(/[\r\n]+/g, " ")
                      .replace(/\u00A0/g, " ")
                      .replace(/\u200B/g, "")
                      .replace(/\u00AD/g, "")
                      .replace(/\s+/g, " ")
                      .trim()
                      .toLowerCase();
                    const subj = (subject || "").toLowerCase();
                    if (
                      subj.includes("thank you for your interest") &&
                      rejectRegex.test(body)
                    ) {
                      return null; // skip
                    }

                    return {
                      id: mid,
                      candidateId: freshCandidate.id,
                      createdAt: msgDateUTC,
                      from: fromHeader,
                    };
                  } catch (err) {
                    // log but don't crash whole candidate processing
                    log(
                      `Failed to fetch message ${mid} for ${freshCandidate.email}:`,
                      err.message || err
                    );
                    return null;
                  }
                })
              )
            );

            const toInsert = fetchedMsgs.filter(Boolean);
            if (toInsert.length === 0) return;

            // Insert messages in bulk (skip duplicates)
            // createMany does not run hooks but is fast. It supports skipDuplicates.
            try {
              await prisma.message.createMany({
                data: toInsert.map((m) => ({
                  id: m.id,
                  candidateId: m.candidateId,
                  createdAt: m.createdAt,
                  from: m.from,
                })),
                skipDuplicates: true,
              });
            } catch (err) {
              log(
                `createMany error for candidate ${freshCandidate.id}:`,
                err.message || err
              );
              // Fall back to per-row inserts if needed (rare)
              for (const m of toInsert) {
                try {
                  await prisma.message.create({
                    data: {
                      id: m.id,
                      candidateId: m.candidateId,
                      createdAt: m.createdAt,
                      from: m.from,
                    },
                  });
                } catch (e) {
                  if (e.code === "P2002") continue;
                  if (e.code === "P2003") {
                    deletedCandidates.add(freshCandidate.id);
                    break;
                  }
                  throw e;
                }
              }
            }

            // After inserting messages, recompute exact counts and write into candidate row
            await updateCandidateCounts(freshCandidate.id);
          } catch (err) {
            // Handle OAuth invalid_grant or expired tokens
            log(`Error processing ${candidate.email}:`, err.message || err);
            if (
              err.code === 401 ||
              (err.errors && err.errors[0]?.reason === "invalid_grant")
            ) {
              try {
                await prisma.candidate.update({
                  where: { id: candidate.id },
                  data: { accessToken: null, refreshToken: null },
                });
                log(
                  `Tokens cleared for ${candidate.email} due to invalid_grant.`
                );
              } catch (e) {
                log("Error clearing tokens:", e);
              }
            }
          }
        })
      )
    );

    // Cleanup deletedCandidates set entries that actually no longer exist
    for (const id of Array.from(deletedCandidates)) {
      const exists = await prisma.candidate.findUnique({ where: { id } });
      if (!exists) {
        deletedCandidates.delete(id);
      }
    }
  } catch (err) {
    log("checkMailsAndUpdateCount error:", err);
  } finally {
    isCronRunning = false;
    log("Cron finished.");
  }
}

// -------------------- SCHEDULE CRON --------------------
cron.schedule(`*/${CRON_INTERVAL} * * * *`, async () => {
  log("⏰ Running mail check every", CRON_INTERVAL, "minutes");
  await checkMailsAndUpdateCount();
});

// -------------------- GET CANDIDATES --------------------
app.get("/candidates", async (req, res) => {
  try {
    // Fetch candidate rows (counts stored here)
    const candidates = await prisma.candidate.findMany({
      orderBy: { createdAt: "desc" },
    });

    // Build a map of today's message counts grouped by candidate (efficient single query)
    const todayMap = await getTodayCountsGrouped();

    const result = candidates.map((c) => ({
      id: c.id,
      name: c.name,
      email: c.email,
      totalCount: c.count || 0,
      platformCount: c.platformCount || 0,
      companyCount: c.companyCount || 0,
      dailyCount: todayMap[c.id] || 0,
      accessToken: c.accessToken,
    }));

    res.json(result);
  } catch (err) {
    log("Get candidates error:", err);
    res.status(500).json({ error: "Failed to fetch candidates" });
  }
});

// -------------------- REPORT --------------------
app.get("/report", async (req, res) => {
  try {
    const { candidateId, from, to } = req.query;
    if (!candidateId || !from || !to)
      return res
        .status(400)
        .json({ error: "candidateId, from, and to required" });

    const candidate = await prisma.candidate.findUnique({
      where: { id: parseInt(candidateId) },
    });
    if (!candidate)
      return res.status(404).json({ error: "Candidate not found" });

    const fromDateUTC = moment
      .tz(`${from} 00:00:00`, "YYYY-MM-DD HH:mm:ss", "America/New_York")
      .utc()
      .toDate();
    const toDateUTC = moment
      .tz(`${to} 23:59:59`, "YYYY-MM-DD HH:mm:ss", "America/New_York")
      .utc()
      .toDate();

    const messages = await prisma.message.findMany({
      where: {
        candidateId: candidate.id,
        createdAt: { gte: fromDateUTC, lte: toDateUTC },
      },
      orderBy: { createdAt: "asc" },
    });

    const dailyMap = {};
    messages.forEach((msg) => {
      const estDate = moment(msg.createdAt)
        .tz("America/New_York")
        .format("YYYY-MM-DD");
      if (!dailyMap[estDate])
        dailyMap[estDate] = { count: 0, platformCount: 0, companyCount: 0 };
      dailyMap[estDate].count++;
      const source = detectMailSource(msg.from);
      if (source === "platform") dailyMap[estDate].platformCount++;
      else dailyMap[estDate].companyCount++;
    });

    const allDates = [];
    let curr = moment.tz(from, "America/New_York");
    const end = moment.tz(to, "America/New_York");
    while (curr.isSameOrBefore(end)) {
      const day = curr.day();
      if (day !== 0 && day !== 6) {
        const dateStr = curr.format("YYYY-MM-DD");
        allDates.push({
          cycleStart: dateStr,
          count: dailyMap[dateStr]?.count || 0,
          platformCount: dailyMap[dateStr]?.platformCount || 0,
          companyCount: dailyMap[dateStr]?.companyCount || 0,
        });
      }
      curr.add(1, "day");
    }

    const totalCount = allDates.reduce((sum, d) => sum + d.count, 0);
    const platformCountTotal = allDates.reduce(
      (sum, d) => sum + d.platformCount,
      0
    );
    const companyCountTotal = allDates.reduce(
      (sum, d) => sum + d.companyCount,
      0
    );

    res.json({
      totalCount,
      platformCountTotal,
      companyCountTotal,
      dailyCounts: allDates,
    });
  } catch (err) {
    log("Report fetch error:", err);
    res.status(500).json({ error: "Failed to fetch report" });
  }
});

// -------------------- START SERVER --------------------
app.listen(PORT, () => log(`Server running on port ${PORT}`));











// require("dotenv").config();
// const express = require("express");
// const cors = require("cors");
// const { PrismaClient } = require("@prisma/client");
// const { google } = require("googleapis");
// const cron = require("node-cron");
// const jwt = require("jsonwebtoken");
// const moment = require("moment-timezone");
// const pLimit = require("p-limit").default;

// const prisma = new PrismaClient();
// const app = express();
// app.use(cors());
// app.use(express.json());

// const PORT = process.env.PORT || 5000;
// const CLIENT_ID = process.env.CLIENT_ID || "";
// const CLIENT_SECRET = process.env.CLIENT_SECRET || "";
// const REDIRECT_URI =
//   process.env.REDIRECT_URI || "http://localhost:5000/oauth2callback";
// const CRON_INTERVAL = process.env.CRON_INTERVAL || 2; // minutes
// const PARALLEL_LIMIT = parseInt(process.env.PARALLEL_LIMIT || "8", 10); // default 8
// const PER_MESSAGE_LIMIT = parseInt(process.env.PER_MESSAGE_LIMIT || "5", 10); // per-candidate message fetch concurrency

// let isCronRunning = false;
// const deletedCandidates = new Set();

// // -------------------- HELPERS --------------------
// function log(...args) {
//   console.log(new Date().toISOString(), ...args);
// }

// function detectMailSource(fromEmail) {
//   if (!fromEmail || fromEmail === "Unknown") return "company";
//   const email = fromEmail.toLowerCase();
//   const platforms = [
//     "linkedin.com",
//     "indeed.com",
//     "glassdoor.com",
//     "simplyhired.com",
//     "dice.com",
//     "monster.com",
//     "careerbuilder.com",
//     "apexsystems.com",
//     "ziprecruiter.com",
//     "randstad.com",
//     "roberthalf.com",
//     "brooksource.com",
//     "insightglobal.com",
//     "teksystems.com",
//     "kforce.com",
//     "levels.fyi",
//     "talenty.io",
//     "jobright.com",
//     "swooped.com",
//     "simplify.com",
//     "builtin.com",
//     "workable.com",
//   ];
//   return platforms.some((d) => email.includes(d)) ? "platform" : "company";
// }

// function extractAllTextFromPayload(payload) {
//   let acc = "";
//   function walk(part) {
//     if (!part) return;
//     if (part.body && part.body.data) {
//       try {
//         acc += Buffer.from(part.body.data, "base64").toString("utf-8") + " ";
//       } catch (e) {}
//     }
//     if (part.parts && Array.isArray(part.parts)) part.parts.forEach(walk);
//   }
//   walk(payload);
//   acc = acc.replace(/<[^>]+>/g, " ");
//   acc = acc.replace(/&nbsp;|&amp;|&lt;|&gt;|&quot;|&#39;/g, " ");
//   return acc;
// }

// // Recompute exact counts from messages table and write into candidate row (atomic-ish)
// async function updateCandidateCounts(candidateId) {
//   // Count all messages for candidate
//   const total = await prisma.message.count({ where: { candidateId } });
//   // Count platform messages
//   // We can't do detectMailSource inside DB, so fetch counts grouped by source in JS:
//   const msgs = await prisma.message.findMany({
//     where: { candidateId },
//     select: { from: true },
//   });
//   let platformCount = 0;
//   for (const m of msgs)
//     if (detectMailSource(m.from) === "platform") platformCount++;
//   const companyCount = total - platformCount;

//   await prisma.candidate.update({
//     where: { id: candidateId },
//     data: { count: total, platformCount, companyCount },
//   });
//   log(
//     `Counts updated for candidate ${candidateId}: total=${total}, platform=${platformCount}, company=${companyCount}`
//   );
// }
                                                                                                                                                                                                                                                  
// // Get today's counts grouped by candidate (EST) — used for GET /candidates dailyCount
// async function getTodayCountsGrouped() {
//   const startEST = moment.tz("America/New_York").startOf("day").utc().toDate();
//   const endEST = moment.tz("America/New_York").endOf("day").utc().toDate();

//   // Group by candidateId: prisma.groupBy
//   // NOTE: groupBy available in Prisma; this returns array of { candidateId, _count: { id } }
//   const groups = await prisma.message.groupBy({
//     by: ["candidateId"],
//     where: { createdAt: { gte: startEST, lte: endEST } },
//     _count: { id: true },
//   });

//   const map = {};
//   for (const g of groups) map[g.candidateId] = g._count.id;
//   return map;
// }

// // -------------------- ROUTES --------------------
// app.get("/", (req, res) => res.send({ status: "ok" }));

// app.post("/login", async (req, res) => {
//   const { username, password } = req.body;
//   try {
//     const admin = await prisma.admin.findFirst();
//     if (!admin)
//       return res
//         .status(404)
//         .json({
//           error:
//             "No admin found. Please set credentials first via Forgot Password.",
//         });
//     if (admin.username !== username || admin.password !== password)
//       return res.status(401).json({ error: "Invalid username or password" });
//     const token = jwt.sign(
//       { username },
//       process.env.JWT_SECRET || "supersecretkey",
//       { expiresIn: "1h" }
//     );
//     res.json({ token, username });
//   } catch (err) {
//     log("Login error:", err);
//     res.status(500).json({ error: "Login failed" });
//   }
// });

// app.post("/forgot-password-question", async (req, res) => {
//   try {
//     let admin = await prisma.admin.findFirst();
//     if (!admin) {
//       admin = await prisma.admin.create({
//         data: {
//           username: "",
//           password: "",
//           question: "What happened on your birthday?",
//           answer: "default",
//         },
//       });
//     }
//     res.json({ question: admin.question });
//   } catch (err) {
//     log("Forgot question error:", err);
//     res.status(500).json({ error: "Failed to get question" });
//   }
// });

// app.post("/verify-answer", async (req, res) => {
//   const { answer } = req.body;
//   try {
//     const admin = await prisma.admin.findFirst();
//     if (!admin) return res.status(404).json({ error: "No admin found" });
//     if (
//       (answer || "").trim().toLowerCase() !==
//       (admin.answer || "").trim().toLowerCase()
//     )
//       return res.status(401).json({ error: "Incorrect answer" });
//     res.json({ success: true });
//   } catch (err) {
//     log("Verify answer error:", err);
//     res.status(500).json({ error: "Verification failed" });
//   }
// });

// app.post("/reset-credentials", async (req, res) => {
//   const { newUsername, newPassword, confirmPassword } = req.body;
//   if (newPassword !== confirmPassword)
//     return res.status(400).json({ error: "Passwords do not match" });
//   try {
//     let admin = await prisma.admin.findFirst();
//     if (!admin) {
//       admin = await prisma.admin.create({
//         data: {
//           username: newUsername,
//           password: newPassword,
//           question: "What happened on your birthday?",
//           answer: "default",
//         },
//       });
//     } else {
//       await prisma.admin.update({
//         where: { id: admin.id },
//         data: { username: newUsername, password: newPassword },
//       });
//     }
//     res.json({ success: true, message: "Credentials updated successfully" });
//   } catch (err) {
//     log("Reset credentials error:", err);
//     res.status(500).json({ error: "Failed to update credentials" });
//   }
// });

// app.post("/candidates", async (req, res) => {
//   const { name, email } = req.body;
//   if (!name || !email)
//     return res.status(400).json({ error: "name and email required" });
//   try {
//     const newCandidate = await prisma.candidate.create({
//       data: {
//         name,
//         email: email.toLowerCase().trim(),
//         count: 0,
//         platformCount: 0,
//         companyCount: 0,
//       },
//     });
//     res.status(201).json(newCandidate);
//   } catch (err) {
//     log("Error adding candidate:", err);
//     if (err.code === "P2002")
//       return res
//         .status(409)
//         .json({ error: "Candidate with this email already exists" });
//     res.status(500).json({ error: "Failed to add candidate" });
//   }
// });

// app.delete("/candidates/:id", async (req, res) => {
//   try {
//     const id = parseInt(req.params.id);
//     await prisma.$transaction([
//       prisma.message.deleteMany({ where: { candidateId: id } }),
//       prisma.candidate.delete({ where: { id } }),
//     ]);
//     deletedCandidates.add(id);
//     res.json({ success: true, message: "Candidate deleted" });
//   } catch (err) {
//     log("Delete candidate error:", err);
//     res.status(500).json({ error: "Failed to delete candidate" });
//   }
// });

// // OAuth routes
// app.get("/auth/:candidateId", (req, res) => {
//   const { candidateId } = req.params;
//   const oAuth2Client = new google.auth.OAuth2(
//     CLIENT_ID,
//     CLIENT_SECRET,
//     REDIRECT_URI
//   );
//   const authUrl = oAuth2Client.generateAuthUrl({
//     access_type: "offline",
//     scope: ["https://www.googleapis.com/auth/gmail.readonly"],
//     state: candidateId,
//     prompt: "consent",
//   });
//   res.redirect(authUrl);
// });

// app.get("/oauth2callback", async (req, res) => {
//   try {
//     const code = req.query.code;
//     const candidateId = req.query.state;
//     if (!code || !candidateId)
//       return res.status(400).send("Missing code or state.");
//     const oAuth2Client = new google.auth.OAuth2(
//       CLIENT_ID,
//       CLIENT_SECRET,
//       REDIRECT_URI
//     );
//     const { tokens } = await oAuth2Client.getToken(code);
//     oAuth2Client.setCredentials(tokens);
//     const profile = await google
//       .gmail({ version: "v1", auth: oAuth2Client })
//       .users.getProfile({ userId: "me" });
//     const googleEmail = profile?.data?.emailAddress || "";
//     const candidate = await prisma.candidate.findUnique({
//       where: { id: parseInt(candidateId) },
//     });
//     if (!candidate) return res.status(404).send("Candidate not found.");
//     if (
//       candidate.email.toLowerCase().trim() !== googleEmail.toLowerCase().trim()
//     )
//       return res
//         .status(400)
//         .send(
//           `Authorized Google account (${googleEmail}) does not match candidate email (${candidate.email}).`
//         );
//     await prisma.candidate.update({
//       where: { id: candidate.id },
//       data: {
//         accessToken: tokens.access_token || null,
//         refreshToken: tokens.refresh_token || null,
//       },
//     });
//     res.send("✅ OAuth Success — account verified and tokens saved.");
//   } catch (err) {
//     log("OAuth callback error:", err);
//     res.status(500).send("OAuth failed");
//   }
// });

// // -------------------- MAIL CHECK & PROCESS --------------------
// async function checkMailsAndUpdateCount() {
//   if (isCronRunning) {
//     log("Cron already running — skipping this run.");
//     return;
//   }
//   isCronRunning = true;
//   log("Cron started.");

//   const subjects = [
//     "Thank you for applying",
//     "Thank you for applying!",
//     "Thanks for applying",
//     "We received your",
//     "Application Received",
//     "Your application for the position",
//     "Your recent application for the position",
//     "we've received",
//     "We have successfully received your application",
//     "Submitted:",
//     "we have received",
//     "submitted",
//     "your application was sent",
//     "Submission",
//     "Thank you for your application",
//     "Thank you for your application!",
//     "Thank you for the application",
//     "Application was received",
//     "Thanks for your application",
//     "Thanks for completing your application",
//     "has been received",
//     "Indeed Application:",
//     "We received your application",
//     "we received your job application",
//     "we received job application",
//     "Application Acknowledgement",
//     "Thank you for your interest",
//     "Thank you for your job application",
//     "your resume was received",
//     "Thank you for submitting your application",
//   ];
//   const query = "subject:(" + subjects.map((s) => `"${s}"`).join(" OR ") + ")";
//   const maxFetch = 100000;
//   const rejectRegex =
//     /(not|won't|unable|unfortunate|unfortunately| other candidates|with other candidates|regret to inform|declined|position has been filled|no longer under consideration|another candidate)/i;

//   try {
//     const candidates = await prisma.candidate.findMany({
//       where: { refreshToken: { not: null } },
//     });
//     if (!candidates || candidates.length === 0) {
//       log("No candidates with refreshToken found.");
//       return;
//     }

//     const limit = pLimit(PARALLEL_LIMIT);

//     await Promise.all(
//       candidates.map((candidate) =>
//         limit(async () => {
//           if (deletedCandidates.has(candidate.id)) return;

//           // re-check candidate existence
//           const freshCandidate = await prisma.candidate.findUnique({
//             where: { id: candidate.id },
//           });
//           if (!freshCandidate) {
//             deletedCandidates.add(candidate.id);
//             return;
//           }
//           if (!freshCandidate.accessToken && !freshCandidate.refreshToken)
//             return;

//           try {
//             const client = new google.auth.OAuth2(
//               CLIENT_ID,
//               CLIENT_SECRET,
//               REDIRECT_URI
//             );
//             client.setCredentials({
//               access_token: freshCandidate.accessToken,
//               refresh_token: freshCandidate.refreshToken,
//             });

//             // Try to get an access token (this can trigger refresh if refresh_token present)
//             try {
//               await client.getAccessToken();
//             } catch (e) {
//               log(
//                 `getAccessToken warning for ${freshCandidate.email}:`,
//                 e.message || e
//               );
//             }

//             const gmail = google.gmail({ version: "v1", auth: client });

//             // List message ids matching query (paginate)
//             let allMessages = [];
//             let nextPageToken = null;
//             do {
//               const listRes = await gmail.users.messages.list({
//                 userId: "me",
//                 q: query,
//                 labelIds: ["INBOX"],
//                 maxResults: 100,
//                 pageToken: nextPageToken,
//               });
//               if (listRes.data?.messages)
//                 allMessages = allMessages.concat(listRes.data.messages);
//               nextPageToken = listRes.data?.nextPageToken;
//               if (allMessages.length >= maxFetch) break;
//             } while (nextPageToken);                                                                                                                                                                                                                                                                                                              

//             if (!allMessages || allMessages.length === 0) return;
//             allMessages = allMessages.slice(0, maxFetch);

//             // Find which message ids are new
//             const ids = allMessages.map((m) => m.id);
//             const existing = await prisma.message.findMany({
//               where: { id: { in: ids } },
//               select: { id: true },
//             });
//             const existingIds = new Set(existing.map((e) => e.id));
//             const newIds = ids.filter((id) => !existingIds.has(id));
//             if (newIds.length === 0) return;

//             // Fetch new messages details in parallel (limited)
//             const perMsgLimit = pLimit(PER_MESSAGE_LIMIT);
//             const fetchedMsgs = await Promise.all(
//               newIds.map((mid) =>
//                 perMsgLimit(async () => {
//                   try {
//                     const msgRes = await gmail.users.messages.get({
//                       userId: "me",
//                       id: mid,
//                     });
//                     const msg = msgRes.data;
//                     const msgTime = parseInt(
//                       msg.internalDate || `${Date.now()}`
//                     );
//                     const msgDateUTC = new Date(msgTime);

//                     let fromHeader = "Unknown",
//                       subject = "",
//                       bodyRaw = "";
//                     if (msg.payload?.headers) {
//                       for (const h of msg.payload.headers) {
//                         if (h.name.toLowerCase() === "from")
//                           fromHeader = h.value;
//                         if (h.name.toLowerCase() === "subject")
//                           subject = h.value || "";
//                       }
//                     }
//                     if (msg.payload)
//                       bodyRaw = extractAllTextFromPayload(msg.payload);
//                     if (!bodyRaw || bodyRaw.trim().length < 10) {
//                       try {
//                         const rawMsg = await gmail.users.messages.get({
//                           userId: "me",
//                           id: mid,
//                           format: "raw",
//                         });
//                         bodyRaw = Buffer.from(
//                           rawMsg.data.raw,
//                           "base64"
//                         ).toString("utf-8");
//                       } catch (e) {}
//                     }

//                     const body = (bodyRaw || "")
//                       .replace(/[\r\n]+/g, " ")
//                       .replace(/\u00A0/g, " ")
//                       .replace(/\u200B/g, "")
//                       .replace(/\u00AD/g, "")
//                       .replace(/\s+/g, " ")
//                       .trim()
//                       .toLowerCase();
//                     const subj = (subject || "").toLowerCase();
//                     if (
//                       subj.includes("thank you for your interest") &&
//                       rejectRegex.test(body)
//                     ) {
//                       return null; // skip
//                     }

//                     return {
//                       id: mid,
//                       candidateId: freshCandidate.id,
//                       createdAt: msgDateUTC,
//                       from: fromHeader,
//                     };
//                   } catch (err) {
//                     // log but don't crash whole candidate processing
//                     log(
//                       `Failed to fetch message ${mid} for ${freshCandidate.email}:`,
//                       err.message || err
//                     );
//                     return null;
//                   }
//                 })
//               )
//             );

//             const toInsert = fetchedMsgs.filter(Boolean);
//             if (toInsert.length === 0) return;

//             // Insert messages in bulk (skip duplicates)
//             // createMany does not run hooks but is fast. It supports skipDuplicates.
//             try {
//               await prisma.message.createMany({
//                 data: toInsert.map((m) => ({
//                   id: m.id,
//                   candidateId: m.candidateId,
//                   createdAt: m.createdAt,
//                   from: m.from,
//                 })),
//                 skipDuplicates: true,
//               });
//             } catch (err) {
//               log(
//                 `createMany error for candidate ${freshCandidate.id}:`,
//                 err.message || err
//               );
//               // Fall back to per-row inserts if needed (rare)
//               for (const m of toInsert) {
//                 try {
//                   await prisma.message.create({
//                     data: {
//                       id: m.id,
//                       candidateId: m.candidateId,
//                       createdAt: m.createdAt,
//                       from: m.from,
//                     },
//                   });
//                 } catch (e) {
//                   if (e.code === "P2002") continue;
//                   if (e.code === "P2003") {
//                     deletedCandidates.add(freshCandidate.id);
//                     break;
//                   }
//                   throw e;
//                 }
//               }
//             }

//             // After inserting messages, recompute exact counts and write into candidate row
//             await updateCandidateCounts(freshCandidate.id);
//           } catch (err) {
//             // Handle OAuth invalid_grant or expired tokens
//             log(`Error processing ${candidate.email}:`, err.message || err);
//             if (
//               err.code === 401 ||
//               (err.errors && err.errors[0]?.reason === "invalid_grant")
//             ) {
//               try {
//                 await prisma.candidate.update({
//                   where: { id: candidate.id },
//                   data: { accessToken: null, refreshToken: null },
//                 });
//                 log(
//                   `Tokens cleared for ${candidate.email} due to invalid_grant.`
//                 );
//               } catch (e) {
//                 log("Error clearing tokens:", e);
//               }
//             }
//           }
//         })
//       )
//     );

//     // Cleanup deletedCandidates set entries that actually no longer exist
//     for (const id of Array.from(deletedCandidates)) {
//       const exists = await prisma.candidate.findUnique({ where: { id } });
//       if (!exists) {
//         deletedCandidates.delete(id);
//       }
//     }
//   } catch (err) {
//     log("checkMailsAndUpdateCount error:", err);
//   } finally {
//     isCronRunning = false;
//     log("Cron finished.");
//   }
// }

// // -------------------- SCHEDULE CRON --------------------
// cron.schedule(`*/${CRON_INTERVAL} * * * *`, async () => {
//   log("⏰ Running mail check every", CRON_INTERVAL, "minutes");
//   await checkMailsAndUpdateCount();
// });

// // -------------------- GET CANDIDATES --------------------
// app.get("/candidates", async (req, res) => {
//   try {
//     // Fetch candidate rows (counts stored here)
//     const candidates = await prisma.candidate.findMany({
//       orderBy: { createdAt: "desc" },
//     });

//     // Build a map of today's message counts grouped by candidate (efficient single query)
//     const todayMap = await getTodayCountsGrouped();

//     const result = candidates.map((c) => ({
//       id: c.id,
//       name: c.name,
//       email: c.email,
//       totalCount: c.count || 0,
//       platformCount: c.platformCount || 0,
//       companyCount: c.companyCount || 0,
//       dailyCount: todayMap[c.id] || 0,
//       accessToken: c.accessToken,
//     }));

//     res.json(result);
//   } catch (err) {
//     log("Get candidates error:", err);
//     res.status(500).json({ error: "Failed to fetch candidates" });
//   }
// });

// // -------------------- REPORT --------------------
// app.get("/report", async (req, res) => {
//   try {
//     const { candidateId, from, to } = req.query;
//     if (!candidateId || !from || !to)
//       return res
//         .status(400)
//         .json({ error: "candidateId, from, and to required" });

//     const candidate = await prisma.candidate.findUnique({
//       where: { id: parseInt(candidateId) },
//     });
//     if (!candidate)
//       return res.status(404).json({ error: "Candidate not found" });

//     const fromDateUTC = moment
//       .tz(`${from} 00:00:00`, "YYYY-MM-DD HH:mm:ss", "America/New_York")
//       .utc()
//       .toDate();
//     const toDateUTC = moment
//       .tz(`${to} 23:59:59`, "YYYY-MM-DD HH:mm:ss", "America/New_York")
//       .utc()
//       .toDate();

//     const messages = await prisma.message.findMany({
//       where: {
//         candidateId: candidate.id,
//         createdAt: { gte: fromDateUTC, lte: toDateUTC },
//       },
//       orderBy: { createdAt: "asc" },
//     });

//     const dailyMap = {};
//     messages.forEach((msg) => {
//       const estDate = moment(msg.createdAt)
//         .tz("America/New_York")
//         .format("YYYY-MM-DD");
//       if (!dailyMap[estDate])
//         dailyMap[estDate] = { count: 0, platformCount: 0, companyCount: 0 };
//       dailyMap[estDate].count++;
//       const source = detectMailSource(msg.from);
//       if (source === "platform") dailyMap[estDate].platformCount++;
//       else dailyMap[estDate].companyCount++;
//     });

//     const allDates = [];
//     let curr = moment.tz(from, "America/New_York");
//     const end = moment.tz(to, "America/New_York");
//     while (curr.isSameOrBefore(end)) {
//       const day = curr.day();
//       if (day !== 0 && day !== 6) {
//         const dateStr = curr.format("YYYY-MM-DD");
//         allDates.push({
//           cycleStart: dateStr,
//           count: dailyMap[dateStr]?.count || 0,
//           platformCount: dailyMap[dateStr]?.platformCount || 0,
//           companyCount: dailyMap[dateStr]?.companyCount || 0,
//         });
//       }
//       curr.add(1, "day");
//     }

//     const totalCount = allDates.reduce((sum, d) => sum + d.count, 0);
//     const platformCountTotal = allDates.reduce(
//       (sum, d) => sum + d.platformCount,
//       0
//     );
//     const companyCountTotal = allDates.reduce(
//       (sum, d) => sum + d.companyCount,
//       0
//     );

//     res.json({
//       totalCount,
//       platformCountTotal,
//       companyCountTotal,
//       dailyCounts: allDates,
//     });
//   } catch (err) {
//     log("Report fetch error:", err);
//     res.status(500).json({ error: "Failed to fetch report" });
//   }
// });

// // -------------------- START SERVER --------------------
// app.listen(PORT, () => log(`Server running on port ${PORT}`));

