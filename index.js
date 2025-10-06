require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");
const { google } = require("googleapis");
const cron = require("node-cron");
const jwt = require("jsonwebtoken");
const moment = require("moment-timezone");

const prisma = new PrismaClient();
const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;
const CLIENT_ID = process.env.CLIENT_ID || "";
const CLIENT_SECRET = process.env.CLIENT_SECRET || "";
const REDIRECT_URI = process.env.REDIRECT_URI || "http://localhost:5000/oauth2callback";
const CRON_INTERVAL = process.env.CRON_INTERVAL || 2; // in minutes

// -------------------- HEALTH CHECK --------------------
app.get("/", (req, res) => res.send({ status: "ok" }));

// -------------------- LOGIN --------------------
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const admin = await prisma.admin.findFirst();
    if (!admin) return res.status(404).json({ error: "No admin found. Please set credentials first via Forgot Password." });
    if (admin.username !== username || admin.password !== password)
      return res.status(401).json({ error: "Invalid username or password" });
    const token = jwt.sign({ username }, "supersecretkey", { expiresIn: "1h" });
    res.json({ token, username });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// -------------------- FORGOT PASSWORD (get question) --------------------
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
    console.error("Forgot question error:", err);
    res.status(500).json({ error: "Failed to get question" });
  }
});

// -------------------- VERIFY ANSWER --------------------
app.post("/verify-answer", async (req, res) => {
  const { answer } = req.body;
  try {
    const admin = await prisma.admin.findFirst();
    if (!admin) return res.status(404).json({ error: "No admin found" });

    const provided = (answer || "").trim().toLowerCase();
    const stored = (admin.answer || "").trim().toLowerCase();

    if (provided !== stored) return res.status(401).json({ error: "Incorrect answer" });
    res.json({ success: true });
  } catch (err) {
    console.error("Verify answer error:", err);
    res.status(500).json({ error: "Verification failed" });
  }
});

// -------------------- RESET CREDENTIALS --------------------
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
    console.error("Reset credentials error:", err);
    res.status(500).json({ error: "Failed to update credentials" });
  }
});

// -------------------- ADD CANDIDATE --------------------
app.post("/candidates", async (req, res) => {
  const { name, email } = req.body;
  if (!name || !email)
    return res.status(400).json({ error: "name and email required" });

  try {
    const newCandidate = await prisma.candidate.create({
      data: { name, email, count: 0, platformCount: 0, companyCount: 0 },
    });
    res.status(201).json(newCandidate);
  } catch (err) {
    console.error("Error adding candidate:", err.message || err);
    if (err.code === "P2002")
      return res.status(409).json({ error: "Candidate with this email already exists" });
    res.status(500).json({ error: "Failed to add candidate" });
  }
});

// -------------------- DELETE CANDIDATE --------------------
app.delete("/candidates/:id", async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.message.deleteMany({ where: { candidateId: parseInt(id) } });
    await prisma.candidate.delete({ where: { id: parseInt(id) } });
    res.json({ success: true, message: "Candidate deleted" });
  } catch (err) {
    console.error("Delete candidate error:", err.message || err);
    res.status(500).json({ error: "Failed to delete candidate" });
  }
});

// -------------------- AUTH --------------------
app.get("/auth/:candidateId", async (req, res) => {
  const { candidateId } = req.params;
  const oAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
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

    const oAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);

    const profile = await google.gmail({ version: "v1", auth: oAuth2Client }).users.getProfile({ userId: "me" });
    const googleEmail = profile?.data?.emailAddress || "";

    const candidate = await prisma.candidate.findUnique({ where: { id: parseInt(candidateId) } });
    if (!candidate) return res.status(404).send("Candidate not found.");
    if (candidate.email.toLowerCase().trim() !== googleEmail.toLowerCase().trim())
      return res.status(400).send(`Authorized Google account (${googleEmail}) does not match candidate email (${candidate.email}).`);

    await prisma.candidate.update({
      where: { id: candidate.id },
      data: {
        accessToken: tokens.access_token || null,
        refreshToken: tokens.refresh_token || null,
      },
    });

    res.send("✅ OAuth Success — account verified and tokens saved.");
  } catch (err) {
    console.error("OAuth callback error:", err.message || err);
    res.status(500).send("OAuth failed");
  }
});

// -------------------- DETECT MAIL SOURCE --------------------
function detectMailSource(fromEmail) {
  if (!fromEmail || fromEmail === "Unknown") return "company";
  const email = fromEmail.toLowerCase();
  const platforms = [
    "linkedin.com","indeed.com","glassdoor.com","simplyhired.com","dice.com",
    "monster.com","careerbuilder.com","apexsystems.com","ziprecruiter.com",
    "randstad.com","roberthalf.com","brooksource.com","insightglobal.com",
    "teksystems.com","kforce.com","levels.fyi","talenty.io","jobright.com",
    "swooped.com","simplify.com","builtin.com","workable.com"
  ];
  return platforms.some(domain => email.includes(domain)) ? "platform" : "company";
}

// -------------------- EXTRACT TEXT --------------------
function extractAllTextFromPayload(payload) {
  let acc = "";
  function walk(part) {
    if (!part) return;
    if (part.body && part.body.data) {
      try { acc += Buffer.from(part.body.data, "base64").toString("utf-8") + " "; } catch(e){}
    }
    if (part.parts && Array.isArray(part.parts)) part.parts.forEach(walk);
  }
  walk(payload);
  acc = acc.replace(/<[^>]+>/g, " ");
  acc = acc.replace(/&nbsp;|&amp;|&lt;|&gt;|&quot;|&#39;/g, " ");
  return acc;
}

// -------------------- CHECK MAILS & UPDATE COUNT --------------------
async function checkMailsAndUpdateCount() {
  const subjects = [
    "Thank you for applying","Thank you for applying!","Thanks for applying",
    "We received your","Application Received","Your application for the position",
    "Your recent application for the position","we've received","We have successfully received your application",
    "Submitted:","we have received","submitted","your application was sent",
    "Submission","Thank you for your application","Thank you for your application!",
    "Thank you for the application","Application was received","Thanks for your application",
    "Thanks for completing your application","has been received","Indeed Application:",
    "We received your application","we received your job application",
    "we received job application","Application Acknowledgement","Thank you for your interest",
    "Thank you for your job application","your resume was received","Thank you for submitting your application"
  ];
  const query = "subject:(" + subjects.map(s => `"${s}"`).join(" OR ") + ")";
  const maxFetch = 100000;
  const rejectRegex = /(not|won't|unable|unfortunate|unfortunately|unfortunately,|pursue other candidates|with other candidates|regret to inform|declined|position has been filled|no longer under consideration|unfortunate|another candidate)/i;
  // const forwardRegex = /forwarded message|-----original message-----/i;

  const candidates = await prisma.candidate.findMany({ where: { refreshToken: { not: null } } });
  if (!candidates || candidates.length === 0) return;

  for (const candidate of candidates) {
    if (!candidate.accessToken && !candidate.refreshToken) continue;

    try {
      const client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
      client.setCredentials({ access_token: candidate.accessToken, refresh_token: candidate.refreshToken });
      const gmail = google.gmail({ version: "v1", auth: client });

      let allMessages = [];
      let nextPageToken = null;

      do {
        const listRes = await gmail.users.messages.list({
          userId: "me",
          q: query,
          labelIds: ["INBOX"],
          maxResults: 100,
          pageToken: nextPageToken
        });
        if (listRes.data.messages) allMessages = allMessages.concat(listRes.data.messages);
        nextPageToken = listRes.data.nextPageToken;
        if (allMessages.length >= maxFetch) break;
      } while (nextPageToken);

      allMessages = allMessages.slice(0, maxFetch);

      for (const m of allMessages) {
        const exists = await prisma.message.findUnique({ where: { id: m.id } });
        if (exists) continue;

        const msg = await gmail.users.messages.get({ userId: "me", id: m.id });
        const msgTime = parseInt(msg.data.internalDate);
        const msgDateUTC = new Date(msgTime);

        let fromHeader = "Unknown", subject = "", bodyRaw = "";

        if (msg.data?.payload?.headers) {
          for (const h of msg.data.payload.headers) {
            if (h.name.toLowerCase() === "from") fromHeader = h.value;
            if (h.name.toLowerCase() === "subject") subject = h.value || "";
          }
        }

        if (msg.data?.payload) bodyRaw = extractAllTextFromPayload(msg.data.payload);

        if (!bodyRaw || bodyRaw.trim().length < 10) {
          try {
            const rawMsg = await gmail.users.messages.get({ userId: "me", id: m.id, format: "raw" });
            bodyRaw = Buffer.from(rawMsg.data.raw, "base64").toString("utf-8");
          } catch (e) {}
        }

        let body = bodyRaw.replace(/[\r\n]+/g," ").replace(/\u00A0/g," ").replace(/\u200B/g,"").replace(/\u00AD/g,"").replace(/\s+/g," ").trim().toLowerCase();
        subject = subject.toLowerCase();

        if (subject.includes("thank you for your interest") && (rejectRegex.test(body))) continue;

        const source = detectMailSource(fromHeader);

        await prisma.message.create({ data: { id: m.id, candidateId: candidate.id, createdAt: msgDateUTC, from: fromHeader } });

        const updateTotalData = { count: { increment: 1 } };
        if (source === "platform") updateTotalData.platformCount = { increment: 1 };
        else updateTotalData.companyCount = { increment: 1 };

        await prisma.candidate.update({ where: { id: candidate.id }, data: updateTotalData });
      }

    } catch (err) {
      console.error(`Error processing ${candidate.email}:`, err);
      if (err.code === 401 || (err.errors && err.errors[0]?.reason === "invalid_grant")) {
        console.log(`Tokens invalid for candidate ${candidate.email}, nullifying...`);
        await prisma.candidate.update({ where: { id: candidate.id }, data: { accessToken: null, refreshToken: null } });
      }
    }
  }
}

// -------------------- CRON JOB --------------------

cron.schedule(`*/${CRON_INTERVAL} * * * *`, async () => {
  console.log("⏰ Running mail check every", CRON_INTERVAL, "minutes");
  try {
    await checkMailsAndUpdateCount();
  } catch (err) {
    console.error("Cron job error:", err);
  }
});


// -------------------- GET CANDIDATES --------------------
app.get("/candidates", async (req, res) => {
  try {
    const candidates = await prisma.candidate.findMany({
      include: { messages: true },
      orderBy: { createdAt: "desc" },
    });

    const result = candidates.map((c) => {
      // Get today's date in EST
      const todayEST = moment().tz("America/New_York").format("YYYY-MM-DD");

      // Calculate dailyCount
      let dailyCount = 0;
      c.messages.forEach((msg) => {
        const msgDateEST = moment(msg.createdAt)
          .tz("America/New_York")
          .format("YYYY-MM-DD");
        if (msgDateEST === todayEST) dailyCount++;
      });

      return {
        id: c.id,
        name: c.name,
        email: c.email,
        totalCount: c.count,
        platformCount: c.platformCount,
        companyCount: c.companyCount,
        dailyCount,
        accessToken: c.accessToken,
      };
    });

    res.json(result);
  } catch (err) {
    console.error("Get candidates error:", err);
    res.status(500).json({ error: "Failed to fetch candidates" });
  }
});


// -------------------- REPORT --------------------
app.get("/report", async (req, res) => {
  try {
    const { candidateId, from, to } = req.query;
    if (!candidateId || !from || !to) return res.status(400).json({ error: "candidateId, from, and to required" });

    const candidate = await prisma.candidate.findUnique({ where: { id: parseInt(candidateId) } });
    if (!candidate) return res.status(404).json({ error: "Candidate not found" });

    const fromDateUTC = moment.tz(`${from} 00:00:00`, "YYYY-MM-DD HH:mm:ss", "America/New_York").utc().toDate();
    const toDateUTC = moment.tz(`${to} 23:59:59`, "YYYY-MM-DD HH:mm:ss", "America/New_York").utc().toDate();

    const messages = await prisma.message.findMany({
      where: { candidateId: candidate.id, createdAt: { gte: fromDateUTC, lte: toDateUTC } },
      orderBy: { createdAt: "asc" }
    });

    const dailyMap = {};
    messages.forEach((msg) => {
      const estDate = moment(msg.createdAt).tz("America/New_York").format("YYYY-MM-DD");
      if (!dailyMap[estDate]) dailyMap[estDate] = { count: 0, platformCount: 0, companyCount: 0 };
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
        allDates.push({ cycleStart: dateStr, count: dailyMap[dateStr]?.count || 0, platformCount: dailyMap[dateStr]?.platformCount || 0, companyCount: dailyMap[dateStr]?.companyCount || 0 });
      }
      curr.add(1, "day");
    }

    const totalCount = allDates.reduce((sum, d) => sum + d.count, 0);
    const platformCountTotal = allDates.reduce((sum, d) => sum + d.platformCount, 0);
    const companyCountTotal = allDates.reduce((sum, d) => sum + d.companyCount, 0);

    res.json({ totalCount, platformCountTotal, companyCountTotal, dailyCounts: allDates });
  } catch (err) { console.error("Report fetch error:", err); res.status(500).json({ error: "Failed to fetch report" }); }
});

// -------------------- START SERVER --------------------
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));










// require("dotenv").config();
// const express = require("express");
// const cors = require("cors");
// const { PrismaClient } = require("@prisma/client");
// const { google } = require("googleapis");
// const cron = require("node-cron");
// const jwt = require("jsonwebtoken");
// const moment = require("moment-timezone");

// const prisma = new PrismaClient();
// const app = express();
// app.use(cors());
// app.use(express.json());

// const PORT = process.env.PORT || 5000;
// const CLIENT_ID = process.env.CLIENT_ID || "";
// const CLIENT_SECRET = process.env.CLIENT_SECRET || "";
// const REDIRECT_URI =
//   process.env.REDIRECT_URI || "http://localhost:5000/oauth2callback";
// const CRON_INTERVAL = process.env.CRON_INTERVAL || 2; // in minutes

// // -------------------- HEALTH CHECK --------------------
// app.get("/", (req, res) => res.send({ status: "ok" }));

// // -------------------- LOGIN --------------------
// app.post("/login", async (req, res) => {
//   const { username, password } = req.body;
//   try {
//     const admin = await prisma.admin.findFirst();

//     if (!admin)
//       return res.status(404).json({ error: "No admin found. Please set credentials first via Forgot Password." });

//     if (admin.username !== username || admin.password !== password)
//       return res.status(401).json({ error: "Invalid username or password" });

//     const token = jwt.sign({ username }, "supersecretkey", { expiresIn: "1h" });
//     res.json({ token, username });
//   } catch (err) {
//     console.error("Login error:", err);
//     res.status(500).json({ error: "Login failed" });
//   }
// });

// // -------------------- FORGOT PASSWORD (get question) --------------------
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
//     console.error("Forgot question error:", err);
//     res.status(500).json({ error: "Failed to get question" });
//   }
// });

// // -------------------- VERIFY ANSWER --------------------
// app.post("/verify-answer", async (req, res) => {
//   const { answer } = req.body;
//   try {
//     const admin = await prisma.admin.findFirst();
//     if (!admin) return res.status(404).json({ error: "No admin found" });

//     const provided = (answer || "").trim().toLowerCase();
//     const stored = (admin.answer || "").trim().toLowerCase();

//     if (provided !== stored) return res.status(401).json({ error: "Incorrect answer" });

//     res.json({ success: true });
//   } catch (err) {
//     console.error("Verify answer error:", err);
//     res.status(500).json({ error: "Verification failed" });
//   }
// });

// // -------------------- RESET CREDENTIALS --------------------
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
//     console.error("Reset credentials error:", err);
//     res.status(500).json({ error: "Failed to update credentials" });
//   }
// });

// // -------------------- ADD CANDIDATE --------------------
// app.post("/candidates", async (req, res) => {
//   const { name, email } = req.body;
//   if (!name || !email)
//     return res.status(400).json({ error: "name and email required" });

//   try {
//     const newCandidate = await prisma.candidate.create({
//       data: { name, email, count: 0, platformCount: 0, companyCount: 0 },
//     });
//     res.status(201).json(newCandidate);
//   } catch (err) {
//     console.error("Error adding candidate:", err.message || err);
//     if (err.code === "P2002")
//       return res
//         .status(409)
//         .json({ error: "Candidate with this email already exists" });
//     res.status(500).json({ error: "Failed to add candidate" });
//   }
// });

// // -------------------- DELETE CANDIDATE --------------------
// app.delete("/candidates/:id", async (req, res) => {
//   try {
//     const { id } = req.params;
//     await prisma.message.deleteMany({ where: { candidateId: parseInt(id) } });
//     await prisma.candidate.delete({ where: { id: parseInt(id) } });
//     res.json({ success: true, message: "Candidate deleted" });
//   } catch (err) {
//     console.error("Delete candidate error:", err.message || err);
//     res.status(500).json({ error: "Failed to delete candidate" });
//   }
// });

// // -------------------- AUTH --------------------
// app.get("/auth/:candidateId", async (req, res) => {
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
//     console.error("OAuth callback error:", err.message || err);
//     res.status(500).send("OAuth failed");
//   }
// });

// // -------------------- DETECT MAIL SOURCE --------------------
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

//   return platforms.some((domain) => email.includes(domain))
//     ? "platform"
//     : "company";
// }

// // -------------------- EXTRACT TEXT --------------------
// function extractAllTextFromPayload(payload) {
//   let acc = "";
//   function walk(part) {
//     if (!part) return;
//     if (part.body && part.body.data) {
//       try {
//         acc += Buffer.from(part.body.data, "base64").toString("utf-8") + " ";
//       } catch (e) {}
//     }
//     if (part.parts && Array.isArray(part.parts)) {
//       part.parts.forEach(walk);
//     }
//   }
//   walk(payload);
//   acc = acc.replace(/<[^>]+>/g, " ");
//   acc = acc.replace(/&nbsp;|&amp;|&lt;|&gt;|&quot;|&#39;/g, " ");
//   return acc;
// }

// // -------------------- CHECK MAILS & UPDATE COUNT --------------------
// async function checkMailsAndUpdateCount() {
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

//   const rejectRegex = /(not|won't|unable|unfortunate|unfortunately|unfortunately,|pursue other candidates|with other candidates|regret to inform|declined|position has been filled|no longer under consideration|unfortunate|another candidate)/i;
//   const forwardRegex = /forwarded message|-----original message-----/i;

//   const candidates = await prisma.candidate.findMany({
//     where: { refreshToken: { not: null } },
//   });
//   if (!candidates || candidates.length === 0) return;

//   for (const candidate of candidates) {
//     if (!candidate.accessToken && !candidate.refreshToken) continue;

//     try {
//       const client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
//       client.setCredentials({
//         access_token: candidate.accessToken,
//         refresh_token: candidate.refreshToken,
//       });
//       const gmail = google.gmail({ version: "v1", auth: client });

//       let allMessages = [];
//       let nextPageToken = null;

//       do {
//         const listRes = await gmail.users.messages.list({
//           userId: "me",
//           q: query,
//           labelIds: ["INBOX"],
//           maxResults: 100,
//           pageToken: nextPageToken,
//         });
//         if (listRes.data.messages) allMessages = allMessages.concat(listRes.data.messages);
//         nextPageToken = listRes.data.nextPageToken;
//         if (allMessages.length >= maxFetch) break;
//       } while (nextPageToken);

//       allMessages = allMessages.slice(0, maxFetch);

//       for (const m of allMessages) {
//         const exists = await prisma.message.findUnique({ where: { id: m.id } });
//         if (exists) continue;

//         const msg = await gmail.users.messages.get({ userId: "me", id: m.id });
//         const msgTime = parseInt(msg.data.internalDate);
//         const msgDateUTC = new Date(msgTime);

//         let fromHeader = "Unknown";
//         let subject = "";
//         let bodyRaw = "";

//         if (msg.data?.payload?.headers) {
//           for (const h of msg.data.payload.headers) {
//             if (h.name.toLowerCase() === "from") fromHeader = h.value;
//             if (h.name.toLowerCase() === "subject") subject = h.value || "";
//           }
//         }

//         if (msg.data?.payload) {
//           bodyRaw = extractAllTextFromPayload(msg.data.payload);
//         }

//         if (!bodyRaw || bodyRaw.trim().length < 10) {
//           try {
//             const rawMsg = await gmail.users.messages.get({
//               userId: "me",
//               id: m.id,
//               format: "raw",
//             });
//             bodyRaw = Buffer.from(rawMsg.data.raw, "base64").toString("utf-8");
//           } catch (e) {}
//         }

//         let body = bodyRaw
//           .replace(/[\r\n]+/g, " ")
//           .replace(/\u00A0/g, " ")
//           .replace(/\u200B/g, "")
//           .replace(/\u00AD/g, "")
//           .replace(/\s+/g, " ")
//           .trim()
//           .toLowerCase();
//         subject = subject.toLowerCase();

//         if (
//           subject.includes("thank you for your interest") &&
//           (rejectRegex.test(body) || forwardRegex.test(body))
//         ) {
//           continue;
//         }

//         const source = detectMailSource(fromHeader);

//         await prisma.message.create({
//           data: {
//             id: m.id,
//             candidateId: candidate.id,
//             createdAt: msgDateUTC,
//             from: fromHeader,
//           },
//         });

//         const updateTotalData = { count: { increment: 1 } };
//         if (source === "platform") updateTotalData.platformCount = { increment: 1 };
//         else updateTotalData.companyCount = { increment: 1 };

//         await prisma.candidate.update({
//           where: { id: candidate.id },
//           data: updateTotalData,
//         });
//       }
//     } catch (err) {
//       console.error(`Error processing ${candidate.email}:`, err);

//       // -------------------- TOKEN EXPIRED / INVALID --------------------
//       if (
//         err.code === 401 || // unauthorized                                                                                                                                                             
//         (err.errors && err.errors[0]?.reason === "invalid_grant")
//       ) {
//         console.log(`Tokens invalid for candidate ${candidate.email}, nullifying...`);
//         await prisma.candidate.update({
//           where: { id: candidate.id },
//           data: {
//             accessToken: null,
//             refreshToken: null,
//           },
//         });
//       }
//     }
//   }
// }


// // -------------------- CRON JOB --------------------

// let isRunning = false; // flag to prevent overlapping

// cron.schedule(`*/${CRON_INTERVAL} * * * *`, async () => {
//   if (isRunning) {
//     console.log("⏱️ Previous cron job still running. Skipping this run...");
//     return;
//   }

//   console.log("⏰ Running mail check every", CRON_INTERVAL, "minutes");
//   isRunning = true;

//   try {
//     await checkMailsAndUpdateCount();
//   } catch (err) {
//     console.error("Cron job error:", err);
//   } finally {
//     isRunning = false;
//   }
// });




// // cron.schedule(`*/${CRON_INTERVAL} * * * *`, () => {
// //   console.log("⏰ Running mail check every", CRON_INTERVAL, "minutes");
// //   checkMailsAndUpdateCount();
// // });

// // -------------------- GET CANDIDATES --------------------
// app.get("/candidates", async (req, res) => {
//   try {
//     const candidates = await prisma.candidate.findMany({
//       include: { messages: true },
//       orderBy: { createdAt: "desc" },
//     });

//     const result = candidates.map((c) => {
//       let dailyCount = 0;
//       const todayEST = new Date().toLocaleString("en-US", {
//         timeZone: "America/New_York",
//       });
//       const todayStr = new Date(todayEST).toISOString().split("T")[0];

//       c.messages.forEach((msg) => {
//         const msgEST = new Date(
//           msg.createdAt.toLocaleString("en-US", {
//             timeZone: "America/New_York",
//           })
//         );
//         const msgDateStr = msgEST.toISOString().split("T")[0];
//         if (msgDateStr === todayStr) dailyCount++;
//       });

//       return {
//         id: c.id,
//         name: c.name,
//         email: c.email,
//         totalCount: c.count,
//         platformCount: c.platformCount,
//         companyCount: c.companyCount,
//         dailyCount,
//         accessToken: c.accessToken,
//       };
//     });

//     res.json(result);
//   } catch (err) {
//     console.error("Get candidates error:", err);
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
//     console.error("Report fetch error:", err);
//     res.status(500).json({ error: "Failed to fetch report" });
//   }
// });

// // -------------------- START SERVER --------------------
// app.listen(PORT, () => console.log(`Server running on port ${PORT}`));











// require("dotenv").config();
// const express = require("express");
// const cors = require("cors");
// const { PrismaClient } = require("@prisma/client");
// const { google } = require("googleapis");
// const cron = require("node-cron");
// const jwt = require("jsonwebtoken");
// const moment = require("moment-timezone");

// const prisma = new PrismaClient();
// const app = express();
// app.use(cors());
// app.use(express.json());

// const PORT = process.env.PORT || 5000;
// const CLIENT_ID = process.env.CLIENT_ID || "";
// const CLIENT_SECRET = process.env.CLIENT_SECRET || "";
// const REDIRECT_URI =
//   process.env.REDIRECT_URI || "http://localhost:5000/oauth2callback";
// const CRON_INTERVAL = process.env.CRON_INTERVAL || 2; // in minutes

// // -------------------- HEALTH CHECK --------------------
// app.get("/", (req, res) => res.send({ status: "ok" }));

// // -------------------- LOGIN --------------------
// // -------------------- LOGIN (DB based) --------------------
// app.post("/login", async (req, res) => {
//   const { username, password } = req.body;
//   try {
//     const admin = await prisma.admin.findUnique({ where: { username } });
//     if (!admin || admin.password !== password)
//       return res.status(401).json({ error: "Invalid username or password" });

//     const token = jwt.sign({ username }, "supersecretkey", { expiresIn: "1h" });
//     res.json({ token, username });
//   } catch (err) {
//     console.error("Login error:", err);
//     res.status(500).json({ error: "Login failed" });
//   }
// });

// // -------------------- FORGOT PASSWORD (get question) --------------------
// // -------------------- FORGOT PASSWORD (get question) --------------------
// app.post("/forgot-password-question", async (req, res) => {
//   const { username } = req.body || {};
//   try {
//     let admin = null;

//     if (username && username.trim() !== "") {
//       admin = await prisma.admin.findUnique({ where: { username: username.trim() } });
//     }

//     // fallback: if no admin by username, use the first admin row as default
//     if (!admin) {
//       admin = await prisma.admin.findFirst();
//       if (!admin) return res.status(404).json({ error: "No admin found" });
//     }

//     res.json({ question: admin.question });
//   } catch (err) {
//     console.error("Forgot question error:", err);
//     res.status(500).json({ error: "Failed to get question" });
//   }
// });

// // -------------------- VERIFY ANSWER --------------------
// app.post("/verify-answer", async (req, res) => {
//   const { username, answer } = req.body || {};
//   try {
//     let admin = null;

//     if (username && username.trim() !== "") {
//       admin = await prisma.admin.findUnique({ where: { username: username.trim() } });
//     }

//     // fallback to first admin if username not supplied or not found
//     if (!admin) {
//       admin = await prisma.admin.findFirst();
//       if (!admin) return res.status(404).json({ error: "No admin found" });
//     }

//     // compare answers case-insensitive and trimmed
//     const provided = (answer || "").trim().toLowerCase();
//     const stored = (admin.answer || "").trim().toLowerCase();

//     if (provided !== stored) {
//       return res.status(401).json({ error: "Incorrect answer" });
//     }

//     res.json({ success: true });
//   } catch (err) {
//     console.error("Verify answer error:", err);
//     res.status(500).json({ error: "Verification failed" });
//   }
// });


// // -------------------- RESET CREDENTIALS --------------------
// app.post("/reset-credentials", async (req, res) => {
//   const { username, newUsername, newPassword, confirmPassword } = req.body;
//   if (newPassword !== confirmPassword)
//     return res.status(400).json({ error: "Passwords do not match" });

//   try {
//     const admin = await prisma.admin.findUnique({ where: { username } });
//     if (!admin)
//       return res.status(404).json({ error: "User not found" });

//     await prisma.admin.update({
//       where: { id: admin.id },
//       data: { username: newUsername, password: newPassword },
//     });
//     res.json({ success: true, message: "Credentials updated successfully" });
//   } catch (err) {
//     console.error("Reset credentials error:", err);
//     res.status(500).json({ error: "Failed to update credentials" });
//   }
// });


// // -------------------- ADD CANDIDATE --------------------
// app.post("/candidates", async (req, res) => {
//   const { name, email } = req.body;
//   if (!name || !email)
//     return res.status(400).json({ error: "name and email required" });

//   try {
//     const newCandidate = await prisma.candidate.create({
//       data: { name, email, count: 0, platformCount: 0, companyCount: 0 },
//     });
//     res.status(201).json(newCandidate);
//   } catch (err) {
//     console.error("Error adding candidate:", err.message || err);
//     if (err.code === "P2002")
//       return res
//         .status(409)
//         .json({ error: "Candidate with this email already exists" });
//     res.status(500).json({ error: "Failed to add candidate" });
//   }
// });

// // -------------------- DELETE CANDIDATE --------------------
// app.delete("/candidates/:id", async (req, res) => {
//   try {
//     const { id } = req.params;
//     await prisma.message.deleteMany({ where: { candidateId: parseInt(id) } });
//     await prisma.candidate.delete({ where: { id: parseInt(id) } });
//     res.json({ success: true, message: "Candidate deleted" });
//   } catch (err) {
//     console.error("Delete candidate error:", err.message || err);
//     res.status(500).json({ error: "Failed to delete candidate" });
//   }
// });

// // -------------------- AUTH --------------------
// app.get("/auth/:candidateId", async (req, res) => {
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
//     console.error("OAuth callback error:", err.message || err);
//     res.status(500).send("OAuth failed");
//   }
// });

// // -------------------- DETECT MAIL SOURCE --------------------
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

//   return platforms.some((domain) => email.includes(domain))
//     ? "platform"
//     : "company";
// }

// // -------------------- CHECK MAILS & UPDATE COUNT --------------------
// function extractAllTextFromPayload(payload) {
//   let acc = "";

//   function walk(part) {
//     if (!part) return;
//     if (part.body && part.body.data) {
//       try {
//         acc += Buffer.from(part.body.data, "base64").toString("utf-8") + " ";
//       } catch (e) {}
//     }
//     if (part.parts && Array.isArray(part.parts)) {
//       part.parts.forEach(walk);
//     }
//   }

//   walk(payload);
//   acc = acc.replace(/<[^>]+>/g, " ");
//   acc = acc.replace(/&nbsp;|&amp;|&lt;|&gt;|&quot;|&#39;/g, " ");
//   return acc;
// }
// async function checkMailsAndUpdateCount() {
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

//   const rejectRegex = /(not|won't|unable|unfortunate|unfortunately|unfortunately,|pursue other candidates|with other candidates|regret to inform|declined|position has been filled|no longer under consideration|unfortunate|another candidate|another candidate.)/i;
//   const forwardRegex = /forwarded message|-----original message-----/i;

//   const candidates = await prisma.candidate.findMany({
//     where: { refreshToken: { not: null } },
//   });
//   if (!candidates || candidates.length === 0) return;

//   for (const candidate of candidates) {
//     if (!candidate.accessToken && !candidate.refreshToken) continue;

//     try {
//       const client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
//       client.setCredentials({
//         access_token: candidate.accessToken,
//         refresh_token: candidate.refreshToken,
//       });
//       const gmail = google.gmail({ version: "v1", auth: client });

//       let allMessages = [];
//       let nextPageToken = null;

//       do {
//         const listRes = await gmail.users.messages.list({
//           userId: "me",
//           q: query,
//           labelIds: ["INBOX"],
//           maxResults: 100,
//           pageToken: nextPageToken,
//         });
//         if (listRes.data.messages) allMessages = allMessages.concat(listRes.data.messages);
//         nextPageToken = listRes.data.nextPageToken;
//         if (allMessages.length >= maxFetch) break;
//       } while (nextPageToken);

//       allMessages = allMessages.slice(0, maxFetch);

//       for (const m of allMessages) {
//         const exists = await prisma.message.findUnique({ where: { id: m.id } });
//         if (exists) continue;

//         const msg = await gmail.users.messages.get({ userId: "me", id: m.id });
//         const msgTime = parseInt(msg.data.internalDate);
//         const msgDateUTC = new Date(msgTime);

//         let fromHeader = "Unknown";
//         let subject = "";
//         let bodyRaw = "";

//         if (msg.data?.payload?.headers) {
//           for (const h of msg.data.payload.headers) {
//             if (h.name.toLowerCase() === "from") fromHeader = h.value;
//             if (h.name.toLowerCase() === "subject") subject = h.value || "";
//           }
//         }

//         if (msg.data?.payload) {
//           bodyRaw = extractAllTextFromPayload(msg.data.payload);
//         }

//         if (!bodyRaw || bodyRaw.trim().length < 10) {
//           try {
//             const rawMsg = await gmail.users.messages.get({
//               userId: "me",
//               id: m.id,
//               format: "raw",
//             });
//             bodyRaw = Buffer.from(rawMsg.data.raw, "base64").toString("utf-8");
//           } catch (e) {}
//         }

//         let body = bodyRaw
//           .replace(/[\r\n]+/g, " ")
//           .replace(/\u00A0/g, " ")
//           .replace(/\u200B/g, "")
//           .replace(/\u00AD/g, "")
//           .replace(/\s+/g, " ")
//           .trim()
//           .toLowerCase();
//         subject = subject.toLowerCase();

//         if (
//           subject.includes("thank you for your interest") &&
//           (rejectRegex.test(body) || forwardRegex.test(body))
//         ) {
//           continue;
//         }

//         const source = detectMailSource(fromHeader);

//         await prisma.message.create({
//           data: {
//             id: m.id,
//             candidateId: candidate.id,
//             createdAt: msgDateUTC,
//             from: fromHeader,
//           },
//         });

//         const updateTotalData = { count: { increment: 1 } };
//         if (source === "platform") updateTotalData.platformCount = { increment: 1 };
//         else updateTotalData.companyCount = { increment: 1 };

//         await prisma.candidate.update({
//           where: { id: candidate.id },
//           data: updateTotalData,
//         });
//       }
//     } catch (err) {
//       console.error(`Error processing ${candidate.email}:`, err);

//       // -------------------- TOKEN EXPIRED / INVALID --------------------
//       if (
//         err.code === 401 || // unauthorized                                                                                                                                                             
//         (err.errors && err.errors[0]?.reason === "invalid_grant")
//       ) {
//         console.log(`Tokens invalid for candidate ${candidate.email}, nullifying...`);
//         await prisma.candidate.update({
//           where: { id: candidate.id },
//           data: {
//             accessToken: null,
//             refreshToken: null,
//           },
//         });
//       }
//     }
//   }
// }





// // -------------------- CRON JOB --------------------
// cron.schedule(`*/${CRON_INTERVAL} * * * *`, () => {
//   console.log("⏰ Running mail check every", CRON_INTERVAL, "minutes");
//   checkMailsAndUpdateCount();
// });

// // -------------------- GET CANDIDATES --------------------
// app.get("/candidates", async (req, res) => {
//   try {
//     const candidates = await prisma.candidate.findMany({
//       include: { messages: true },
//       orderBy: { createdAt: "desc" },
//     });

//     const result = candidates.map((c) => {
//       let dailyCount = 0;
//       const todayEST = new Date().toLocaleString("en-US", {
//         timeZone: "America/New_York",
//       });
//       const todayStr = new Date(todayEST).toISOString().split("T")[0];

//       c.messages.forEach((msg) => {
//         const msgEST = new Date(
//           msg.createdAt.toLocaleString("en-US", {
//             timeZone: "America/New_York",
//           })
//         );
//         const msgDateStr = msgEST.toISOString().split("T")[0];
//         if (msgDateStr === todayStr) dailyCount++;
//       });

//       return {
//         id: c.id,
//         name: c.name,
//         email: c.email,
//         totalCount: c.count,
//         platformCount: c.platformCount,
//         companyCount: c.companyCount,
//         dailyCount,
//         accessToken: c.accessToken,
//       };
//     });

//     res.json(result);
//   } catch (err) {
//     console.error("Get candidates error:", err);
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
//     console.error("Report fetch error:", err);
//     res.status(500).json({ error: "Failed to fetch report" });
//   }
// });

// // -------------------- START SERVER --------------------
// app.listen(PORT, () => console.log(`Server running on port ${PORT}`));








// async function checkMailsAndUpdateCount() {
//   const subjects = [
//     "Thank you for applying",
//     "Thank you for applying!",
//     "Submission Received",
//     "Thanks for applying",
//     "Submission Confirmation",
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
//     "submission",
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

//   const query =
//     "subject:(" + subjects.map((s) => `\"${s}\"`).join(" OR ") + ")";
//   const maxFetch = 100000;

//   const rejectRegex =
//     /(not|unable|unfortunately|pursue other candidates|with other candidates|regret to inform|declined|position has been filled|no longer under consideration|unfortunate|another candidate)/i;
//   const forwardRegex = /forwarded message|-----original message-----/i;

//   const candidates = await prisma.candidate.findMany({
//     where: { refreshToken: { not: null } },
//   });
//   if (!candidates || candidates.length === 0) return;

//   for (const candidate of candidates) {
//     if (!candidate.accessToken && !candidate.refreshToken) continue;

//     try {
//       const client = new google.auth.OAuth2(
//         CLIENT_ID,
//         CLIENT_SECRET,
//         REDIRECT_URI
//       );
//       client.setCredentials({
//         access_token: candidate.accessToken,
//         refresh_token: candidate.refreshToken,
//       });
//       const gmail = google.gmail({ version: "v1", auth: client });

//       let allMessages = [];
//       let nextPageToken = null;

//       do {
//         const listRes = await gmail.users.messages.list({
//           userId: "me",
//           q: query,
//           labelIds: ["INBOX"],
//           maxResults: 100,
//           pageToken: nextPageToken,
//         });
//         if (listRes.data.messages)
//           allMessages = allMessages.concat(listRes.data.messages);
//         nextPageToken = listRes.data.nextPageToken;
//         if (allMessages.length >= maxFetch) break;
//       } while (nextPageToken);

//       allMessages = allMessages.slice(0, maxFetch);

//       for (const m of allMessages) {
//         const exists = await prisma.message.findUnique({ where: { id: m.id } });
//         if (exists) continue;

//         const msg = await gmail.users.messages.get({ userId: "me", id: m.id });
//         const msgTime = parseInt(msg.data.internalDate);
//         const msgDateUTC = new Date(msgTime);

//         let fromHeader = "Unknown";
//         let subject = "";
//         let bodyRaw = "";

//         if (msg.data?.payload?.headers) {
//           for (const h of msg.data.payload.headers) {
//             if (h.name.toLowerCase() === "from") fromHeader = h.value;
//             if (h.name.toLowerCase() === "subject") subject = h.value || "";
//           }
//         }

//         if (msg.data?.payload) {
//           bodyRaw = extractAllTextFromPayload(msg.data.payload);
//         }

//         if (!bodyRaw || bodyRaw.trim().length < 10) {
//           try {
//             const rawMsg = await gmail.users.messages.get({
//               userId: "me",
//               id: m.id,
//               format: "raw",
//             });
//             bodyRaw = Buffer.from(rawMsg.data.raw, "base64").toString("utf-8");
//           } catch (e) {}
//         }

//         let body = bodyRaw
//           .replace(/[\r\n]+/g, " ")
//           .replace(/\u00A0/g, " ")
//           .replace(/\u200B/g, "")
//           .replace(/\u00AD/g, "")
//           .replace(/\s+/g, " ")
//           .trim()
//           .toLowerCase();
//         subject = subject.toLowerCase();

//         // Skip rejected or forwarded mails
//         if (
//           subject.includes("thank you for your interest") &&
//           (rejectRegex.test(body) || forwardRegex.test(body))
//         ) {
//           continue;
//         }

//         // ------------------ NEW CHECK ------------------
//         const candidateExists = await prisma.candidate.findUnique({
//           where: { id: candidate.id },
//         });
//         if (!candidateExists) {
//           console.log(
//             `Candidate ${candidate.id} not found, skipping message ${m.id}`
//           );
//           continue;
//         }

//         const source = detectMailSource(fromHeader);

//         await prisma.message.create({
//           data: {
//             id: m.id,
//             candidateId: candidate.id,
//             createdAt: msgDateUTC,
//             from: fromHeader,
//           },
//         });

//         const updateTotalData = { count: { increment: 1 } };
//         if (source === "platform")
//           updateTotalData.platformCount = { increment: 1 };
//         else updateTotalData.companyCount = { increment: 1 };

//         await prisma.candidate.update({
//           where: { id: candidate.id },
//           data: updateTotalData,
//         });
//       }
//     } catch (err) {
//       console.error(`Error processing ${candidate.email}:`, err);
//     }
//   }
// }








// require("dotenv").config();
// const express = require("express");
// const cors = require("cors");
// const { PrismaClient } = require("@prisma/client");
// const { google } = require("googleapis");
// const cron = require("node-cron");
// const jwt = require("jsonwebtoken");
// const moment = require("moment-timezone");

// const prisma = new PrismaClient();
// const app = express();
// app.use(cors());
// app.use(express.json());

// const PORT = process.env.PORT || 5000;
// const CLIENT_ID = process.env.CLIENT_ID || "";
// const CLIENT_SECRET = process.env.CLIENT_SECRET || "";
// const REDIRECT_URI =
//   process.env.REDIRECT_URI || "http://localhost:5000/oauth2callback";
// const CRON_INTERVAL = process.env.CRON_INTERVAL || 2; // in minutes

// // -------------------- HEALTH CHECK --------------------
// app.get("/", (req, res) => res.send({ status: "ok" }));

// // -------------------- LOGIN --------------------
// app.post("/login", (req, res) => {
//   const { username, password } = req.body;
//   const FIXED_USERNAME = "crr7t";
//   const FIXED_PASSWORD = "ramramji";

//   if (username === FIXED_USERNAME && password === FIXED_PASSWORD) {
//     const token = jwt.sign({ username }, "supersecretkey", { expiresIn: "1h" });
//     return res.json({ token, username });
//   }
//   return res.status(401).json({ error: "Invalid username or password" });
// });

// // -------------------- ADD CANDIDATE --------------------
// app.post("/candidates", async (req, res) => {
//   const { name, email } = req.body;
//   if (!name || !email)
//     return res.status(400).json({ error: "name and email required" });

//   try {
//     const newCandidate = await prisma.candidate.create({
//       data: { name, email, count: 0, platformCount: 0, companyCount: 0 },
//     });
//     res.status(201).json(newCandidate);
//   } catch (err) {
//     console.error("Error adding candidate:", err.message || err);
//     if (err.code === "P2002")
//       return res
//         .status(409)
//         .json({ error: "Candidate with this email already exists" });
//     res.status(500).json({ error: "Failed to add candidate" });
//   }
// });

// // -------------------- DELETE CANDIDATE --------------------
// app.delete("/candidates/:id", async (req, res) => {
//   try {
//     const { id } = req.params;
//     await prisma.message.deleteMany({ where: { candidateId: parseInt(id) } });
//     await prisma.candidate.delete({ where: { id: parseInt(id) } });
//     res.json({ success: true, message: "Candidate deleted" });
//   } catch (err) {
//     console.error("Delete candidate error:", err.message || err);
//     res.status(500).json({ error: "Failed to delete candidate" });
//   }
// });

// // -------------------- AUTH --------------------
// app.get("/auth/:candidateId", async (req, res) => {
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
//     console.error("OAuth callback error:", err.message || err);
//     res.status(500).send("OAuth failed");
//   }
// });

// // -------------------- DETECT MAIL SOURCE --------------------
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

//   return platforms.some((domain) => email.includes(domain))
//     ? "platform"
//     : "company";
// }

// // -------------------- CHECK MAILS & UPDATE COUNT --------------------
// // Helper: recursively extract text from payload
// function extractAllTextFromPayload(payload) {
//   let acc = "";

//   function walk(part) {
//     if (!part) return;
//     if (part.body && part.body.data) {
//       try {
//         acc += Buffer.from(part.body.data, "base64").toString("utf-8") + " ";
//       } catch (e) {}
//     }
//     if (part.parts && Array.isArray(part.parts)) {
//       part.parts.forEach(walk);
//     }
//   }

//   walk(payload);
//   // strip tags
//   acc = acc.replace(/<[^>]+>/g, " ");
//   // decode common HTML entities
//   acc = acc.replace(/&nbsp;|&amp;|&lt;|&gt;|&quot;|&#39;/g, " ");
//   return acc;
// }

// async function checkMailsAndUpdateCount() {
//   const subjects = [
//     "Thank you for applying",
//     "Thank you for applying!",
//     "Submission Received",
//     "Thanks for applying",
//     "Submission Confirmation",
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
//     "submission",
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

//   const query =
//     "subject:(" + subjects.map((s) => `\"${s}\"`).join(" OR ") + ")";
//   const maxFetch = 100000;

//   const rejectRegex =
//     /(not|unable|unfortunately|pursue other candidates|with other candidates|regret to inform|declined|position has been filled|no longer under consideration|unfortunate|another candidate)/i;
//   const forwardRegex = /forwarded message|-----original message-----/i;

//   const candidates = await prisma.candidate.findMany({
//     where: { refreshToken: { not: null } },
//   });
//   if (!candidates || candidates.length === 0) return;

//   for (const candidate of candidates) {
//     if (!candidate.accessToken && !candidate.refreshToken) continue;

//     try {
//       const client = new google.auth.OAuth2(
//         CLIENT_ID,
//         CLIENT_SECRET,
//         REDIRECT_URI
//       );
//       client.setCredentials({
//         access_token: candidate.accessToken,
//         refresh_token: candidate.refreshToken,
//       });
//       const gmail = google.gmail({ version: "v1", auth: client });

//       let allMessages = [];
//       let nextPageToken = null;

//       do {
//         const listRes = await gmail.users.messages.list({
//           userId: "me",
//           q: query,
//           labelIds: ["INBOX"],
//           maxResults: 100,
//           pageToken: nextPageToken,
//         });
//         if (listRes.data.messages)
//           allMessages = allMessages.concat(listRes.data.messages);
//         nextPageToken = listRes.data.nextPageToken;
//         if (allMessages.length >= maxFetch) break;
//       } while (nextPageToken);

//       allMessages = allMessages.slice(0, maxFetch);

//       for (const m of allMessages) {
//         const exists = await prisma.message.findUnique({ where: { id: m.id } });
//         if (exists) continue;

//         const msg = await gmail.users.messages.get({ userId: "me", id: m.id });
//         const msgTime = parseInt(msg.data.internalDate);
//         const msgDateUTC = new Date(msgTime);

//         let fromHeader = "Unknown";
//         let subject = "";
//         let bodyRaw = "";

//         if (msg.data?.payload?.headers) {
//           for (const h of msg.data.payload.headers) {
//             if (h.name.toLowerCase() === "from") fromHeader = h.value;
//             if (h.name.toLowerCase() === "subject") subject = h.value || "";
//           }
//         }

//         if (msg.data?.payload) {
//           bodyRaw = extractAllTextFromPayload(msg.data.payload);
//         }

//         if (!bodyRaw || bodyRaw.trim().length < 10) {
//           try {
//             const rawMsg = await gmail.users.messages.get({
//               userId: "me",
//               id: m.id,
//               format: "raw",
//             });
//             bodyRaw = Buffer.from(rawMsg.data.raw, "base64").toString("utf-8");
//           } catch (e) {}
//         }

//         let body = bodyRaw
//           .replace(/[\r\n]+/g, " ")
//           .replace(/\u00A0/g, " ")
//           .replace(/\u200B/g, "")
//           .replace(/\u00AD/g, "")
//           .replace(/\s+/g, " ")
//           .trim()
//           .toLowerCase();
//         subject = subject.toLowerCase();

//         if (
//           subject.includes("thank you for your interest") &&
//           (rejectRegex.test(body) || forwardRegex.test(body))
//         ) {
//           continue;
//         }

//         const source = detectMailSource(fromHeader);

//         // ✅ Safe check: ensure candidate still exists
//         const candidateExists = await prisma.candidate.findUnique({
//           where: { id: candidate.id },
//         });
//         if (!candidateExists) {
//           console.log(`Candidate ${candidate.id} not found, skipping message ${m.id}`);
//           continue;
//         }

//         await prisma.message.create({
//           data: {
//             id: m.id,
//             candidateId: candidate.id,
//             createdAt: msgDateUTC,
//             from: fromHeader,
//           },
//         });

//         const updateTotalData = { count: { increment: 1 } };
//         if (source === "platform") updateTotalData.platformCount = { increment: 1 };
//         else updateTotalData.companyCount = { increment: 1 };

//         await prisma.candidate.update({
//           where: { id: candidate.id },
//           data: updateTotalData,
//         });
//       }
//     } catch (err) {
//       console.error(`Error processing ${candidate.email}:`, err);
//     }
//   }
// }

// // -------------------- CRON JOB --------------------
// cron.schedule(`*/${CRON_INTERVAL} * * * *`, () => {
//   console.log("⏰ Running mail check every", CRON_INTERVAL, "minutes");
//   checkMailsAndUpdateCount();
// });

// // -------------------- GET CANDIDATES --------------------
// app.get("/candidates", async (req, res) => {
//   try {
//     const candidates = await prisma.candidate.findMany({
//       include: { messages: true },
//       orderBy: { createdAt: "desc" },
//     });

//     const result = candidates.map((c) => {
//       let dailyCount = 0;
//       const todayEST = new Date().toLocaleString("en-US", {
//         timeZone: "America/New_York",
//       });
//       const todayStr = new Date(todayEST).toISOString().split("T")[0];

//       c.messages.forEach((msg) => {
//         const msgEST = new Date(
//           msg.createdAt.toLocaleString("en-US", {
//             timeZone: "America/New_York",
//           })
//         );
//         const msgDateStr = msgEST.toISOString().split("T")[0];
//         if (msgDateStr === todayStr) dailyCount++;
//       });

//       return {
//         id: c.id,
//         name: c.name,
//         email: c.email,
//         totalCount: c.count,
//         platformCount: c.platformCount,
//         companyCount: c.companyCount,
//         dailyCount,
//         accessToken: c.accessToken,
//       };
//     });

//     res.json(result);
//   } catch (err) {
//     console.error("Get candidates error:", err);
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
//     console.error("Report fetch error:", err);
//     res.status(500).json({ error: "Failed to fetch report" });
//   }
// });

// // -------------------- START SERVER --------------------
// app.listen(PORT, () => console.log(`Server running on port ${PORT}`));





// require("dotenv").config();
// const express = require("express");
// const cors = require("cors");
// const { PrismaClient } = require("@prisma/client");
// const { google } = require("googleapis");
// const cron = require("node-cron");
// const jwt = require("jsonwebtoken");
// const moment = require("moment-timezone");

// const prisma = new PrismaClient();
// const app = express();
// app.use(cors());
// app.use(express.json());

// const PORT = process.env.PORT || 5000;
// const CLIENT_ID = process.env.CLIENT_ID || "";
// const CLIENT_SECRET = process.env.CLIENT_SECRET || "";
// const REDIRECT_URI =
//   process.env.REDIRECT_URI || "http://localhost:5000/oauth2callback";
// const CRON_INTERVAL = process.env.CRON_INTERVAL || 2; // in minutes

// // -------------------- HEALTH CHECK --------------------
// app.get("/", (req, res) => res.send({ status: "ok" }));

// // -------------------- LOGIN --------------------
// app.post("/login", (req, res) => {
//   const { username, password } = req.body;
//   const FIXED_USERNAME = "crr7t";
//   const FIXED_PASSWORD = "ramramji";

//   if (username === FIXED_USERNAME && password === FIXED_PASSWORD) {
//     const token = jwt.sign({ username }, "supersecretkey", { expiresIn: "1h" });
//     return res.json({ token, username });
//   }
//   return res.status(401).json({ error: "Invalid username or password" });
// });

// // -------------------- ADD CANDIDATE --------------------
// app.post("/candidates", async (req, res) => {
//   const { name, email } = req.body;
//   if (!name || !email)
//     return res.status(400).json({ error: "name and email required" });

//   try {
//     const newCandidate = await prisma.candidate.create({
//       data: { name, email, count: 0, platformCount: 0, companyCount: 0 },
//     });
//     res.status(201).json(newCandidate);
//   } catch (err) {
//     console.error("Error adding candidate:", err.message || err);
//     if (err.code === "P2002")
//       return res
//         .status(409)
//         .json({ error: "Candidate with this email already exists" });
//     res.status(500).json({ error: "Failed to add candidate" });
//   }
// });

// // -------------------- DELETE CANDIDATE --------------------
// app.delete("/candidates/:id", async (req, res) => {
//   try {
//     const { id } = req.params;
//     await prisma.message.deleteMany({ where: { candidateId: parseInt(id) } });
//     await prisma.candidate.delete({ where: { id: parseInt(id) } });
//     res.json({ success: true, message: "Candidate deleted" });
//   } catch (err) {
//     console.error("Delete candidate error:", err.message || err);
//     res.status(500).json({ error: "Failed to delete candidate" });
//   }
// });

// // -------------------- AUTH --------------------
// app.get("/auth/:candidateId", async (req, res) => {
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
//     console.error("OAuth callback error:", err.message || err);
//     res.status(500).send("OAuth failed");
//   }
// });

// // -------------------- DETECT MAIL SOURCE --------------------
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

//   return platforms.some((domain) => email.includes(domain))
//     ? "platform"
//     : "company";
// }

// // -------------------- CHECK MAILS & UPDATE COUNT --------------------
// // Helper: recursively extract text from payload
// function extractAllTextFromPayload(payload) {
//   let acc = "";

//   function walk(part) {
//     if (!part) return;
//     if (part.body && part.body.data) {
//       try {
//         acc += Buffer.from(part.body.data, "base64").toString("utf-8") + " ";
//       } catch (e) {}
//     }
//     if (part.parts && Array.isArray(part.parts)) {
//       part.parts.forEach(walk);
//     }
//   }

//   walk(payload);
//   // strip tags
//   acc = acc.replace(/<[^>]+>/g, " ");
//   // decode common HTML entities
//   acc = acc.replace(/&nbsp;|&amp;|&lt;|&gt;|&quot;|&#39;/g, " ");
//   return acc;
// }

// async function checkMailsAndUpdateCount() {
//   const subjects = [
//     "Thank you for applying",
//     "Thank you for applying!",
//     "Submission Received",
//     "Thanks for applying",
//     "Submission Confirmation",
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
//     "submission",
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

//   const query =
//     "subject:(" + subjects.map((s) => `\"${s}\"`).join(" OR ") + ")";
//   const maxFetch = 100000;

//   // Relaxed reject regex (company mails ke liye)
//   const rejectRegex =
//     /(not|unable|unfortunately|pursue other candidates|with other candidates|regret to inform|declined|position has been filled|no longer under consideration|unfortunate|another candidate)/i;
//   const forwardRegex = /forwarded message|-----original message-----/i;

//   const candidates = await prisma.candidate.findMany({
//     where: { refreshToken: { not: null } },
//   });
//   if (!candidates || candidates.length === 0) return;

//   for (const candidate of candidates) {
//     if (!candidate.accessToken && !candidate.refreshToken) continue;

//     try {
//       const client = new google.auth.OAuth2(
//         CLIENT_ID,
//         CLIENT_SECRET,
//         REDIRECT_URI
//       );
//       client.setCredentials({
//         access_token: candidate.accessToken,
//         refresh_token: candidate.refreshToken,
//       });
//       const gmail = google.gmail({ version: "v1", auth: client });

//       let allMessages = [];
//       let nextPageToken = null;

//       do {
//         const listRes = await gmail.users.messages.list({
//           userId: "me",
//           q: query,
//           labelIds: ["INBOX"],
//           maxResults: 100,
//           pageToken: nextPageToken,
//         });
//         if (listRes.data.messages)
//           allMessages = allMessages.concat(listRes.data.messages);
//         nextPageToken = listRes.data.nextPageToken;
//         if (allMessages.length >= maxFetch) break;
//       } while (nextPageToken);

//       allMessages = allMessages.slice(0, maxFetch);

//       for (const m of allMessages) {
//         const exists = await prisma.message.findUnique({ where: { id: m.id } });
//         if (exists) continue;

//         const msg = await gmail.users.messages.get({ userId: "me", id: m.id });
//         const msgTime = parseInt(msg.data.internalDate);
//         const msgDateUTC = new Date(msgTime);

//         let fromHeader = "Unknown";
//         let subject = "";
//         let bodyRaw = "";

//         if (msg.data?.payload?.headers) {
//           for (const h of msg.data.payload.headers) {
//             if (h.name.toLowerCase() === "from") fromHeader = h.value;
//             if (h.name.toLowerCase() === "subject") subject = h.value || "";
//           }
//         }

//         // Extract body recursively
//         if (msg.data?.payload) {
//           bodyRaw = extractAllTextFromPayload(msg.data.payload);
//         }

//         // Raw fallback if nothing found
//         if (!bodyRaw || bodyRaw.trim().length < 10) {
//           try {
//             const rawMsg = await gmail.users.messages.get({
//               userId: "me",
//               id: m.id,
//               format: "raw",
//             });
//             bodyRaw = Buffer.from(rawMsg.data.raw, "base64").toString("utf-8");
//           } catch (e) {}
//         }

//         // Normalize body & subject
//         let body = bodyRaw
//           .replace(/[\r\n]+/g, " ")
//           .replace(/\u00A0/g, " ") // NBSP
//           .replace(/\u200B/g, "") // zero-width space
//           .replace(/\u00AD/g, "") // soft hyphen
//           .replace(/\s+/g, " ")
//           .trim()
//           .toLowerCase();
//         subject = subject.toLowerCase();
//         // Skip rejected or forwarded mails (subject wise filter)
//    if (
//   subject.includes("thank you for your interest") &&
//   (rejectRegex.test(body) || forwardRegex.test(body))
// ) {
//   continue;
// }


//         const source = detectMailSource(fromHeader);

//         await prisma.message.create({
//           data: {
//             id: m.id,
//             candidateId: candidate.id,
//             createdAt: msgDateUTC,
//             from: fromHeader,
//           },
//         });

//         const updateTotalData = { count: { increment: 1 } };
//         if (source === "platform")
//           updateTotalData.platformCount = { increment: 1 };
//         else updateTotalData.companyCount = { increment: 1 };

//         await prisma.candidate.update({
//           where: { id: candidate.id },
//           data: updateTotalData,
//         });
//       }
//     } catch (err) {
//       console.error(`Error processing ${candidate.email}:`, err);
//     }
//   }
// }


// // -------------------- CRON JOB --------------------
// cron.schedule(`*/${CRON_INTERVAL} * * * *`, () => {
//   console.log("⏰ Running mail check every", CRON_INTERVAL, "minutes");
//   checkMailsAndUpdateCount();
// });

// // -------------------- GET CANDIDATES --------------------
// app.get("/candidates", async (req, res) => {
//   try {
//     const candidates = await prisma.candidate.findMany({
//       include: { messages: true },
//       orderBy: { createdAt: "desc" },
//     });

//     const result = candidates.map((c) => {
//       let dailyCount = 0;
//       const todayEST = new Date().toLocaleString("en-US", {
//         timeZone: "America/New_York",
//       });
//       const todayStr = new Date(todayEST).toISOString().split("T")[0];

//       c.messages.forEach((msg) => {
//         const msgEST = new Date(
//           msg.createdAt.toLocaleString("en-US", {
//             timeZone: "America/New_York",
//           })
//         );
//         const msgDateStr = msgEST.toISOString().split("T")[0];
//         if (msgDateStr === todayStr) dailyCount++;
//       });

//       return {
//         id: c.id,
//         name: c.name,
//         email: c.email,
//         totalCount: c.count,
//         platformCount: c.platformCount,
//         companyCount: c.companyCount,
//         dailyCount,
//         accessToken: c.accessToken,
//       };
//     });

//     res.json(result);
//   } catch (err) {
//     console.error("Get candidates error:", err);
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
//     console.error("Report fetch error:", err);
//     res.status(500).json({ error: "Failed to fetch report" });
//   }
// });

// // -------------------- START SERVER --------------------
// app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

