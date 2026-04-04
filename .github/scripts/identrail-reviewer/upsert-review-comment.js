"use strict";

const crypto = require("crypto");
const fs = require("fs");

const INLINE_MARKER_PREFIX = "<!-- identrail-reviewer:inline:";
const INLINE_MARKER_SUFFIX = " -->";

function normalizePath(value) {
  return String(value || "").trim().replace(/\\/g, "/").replace(/^\.\/+/, "");
}

function formatFindings(findings, maxFindings) {
  const limit = Number.isInteger(maxFindings) && maxFindings > 0 ? maxFindings : findings.length;
  const clipped = findings.slice(0, limit);

  let body = "";
  if (clipped.length > 0) {
    body += "### Findings\n";
    for (const finding of clipped) {
      body += `- [${finding.severity}] ${finding.summary} (${finding.file}:${finding.line})\n`;
      body += `  - Rule: \`${finding.rule_id}\` | Confidence: ${finding.confidence}\n`;
      body += `  - Recommendation: ${finding.recommendation}\n`;
    }
  } else {
    body += "### Findings\n- No deterministic findings.\n";
  }

  if (findings.length > limit) {
    body += `\nAdditional findings omitted: ${findings.length - limit}.\n`;
  }

  return body;
}

function formatAbstentions(abstentions) {
  if (!Array.isArray(abstentions) || abstentions.length === 0) {
    return "";
  }
  let body = "\n### Abstentions\n";
  for (const note of abstentions) {
    body += `- ${note}\n`;
  }
  return body;
}

function formatGate(gate) {
  if (!gate || typeof gate !== "object") {
    return "";
  }

  let body = "";
  if (typeof gate.status === "string") {
    const phase = typeof gate.phase === "string" ? gate.phase : "";
    body += `Gate: **${gate.status}**`;
    if (phase.length > 0) {
      body += ` (phase: \`${phase}\`)`;
    }
    body += "\n";
  }

  if (typeof gate.reason === "string" && gate.reason.length > 0) {
    body += `Gate reason: ${gate.reason}\n`;
  }

  if (Array.isArray(gate.blocking_finding_ids) && gate.blocking_finding_ids.length > 0) {
    body += `Blocking findings: ${gate.blocking_finding_ids.join(", ")}\n`;
  }

  if (body.length > 0) {
    return `${body}\n`;
  }
  return "";
}

function renderBody({ marker, heading, result, gate, maxFindings }) {
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const abstentions = Array.isArray(result.abstentions) ? result.abstentions : [];

  let body = `${marker}\n${heading}\n`;
  body += `Status: **${result.status}**\n\n`;
  body += `${result.summary}\n\n`;
  body += formatGate(gate);
  body += formatFindings(findings, maxFindings);
  body += formatAbstentions(abstentions);
  body += `\n_Reviewer version: ${result.version}_\n`;
  return body;
}

function parseTouchedLines(patch) {
  const touched = new Set();
  if (typeof patch !== "string" || patch.length === 0) {
    return touched;
  }

  const lines = patch.split("\n");
  let nextRightLine = null;
  for (const line of lines) {
    if (line.startsWith("@@")) {
      const match = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
      nextRightLine = match ? Number.parseInt(match[1], 10) : null;
      continue;
    }
    if (nextRightLine === null) {
      continue;
    }
    if (line.startsWith("+") && !line.startsWith("+++")) {
      nextRightLine += 1;
      continue;
    }
    if (line.startsWith("-") && !line.startsWith("---")) {
      continue;
    }
    if (line.startsWith(" ")) {
      touched.add(nextRightLine);
      nextRightLine += 1;
    }
  }
  return touched;
}

function findingInlineFingerprint(finding) {
  const payload = [
    String(finding.rule_id || "").trim(),
    normalizePath(finding.file),
    String(Number(finding.line) || 0),
    String(finding.summary || "").trim(),
  ].join("|");
  return crypto.createHash("sha256").update(payload).digest("hex").slice(0, 24);
}

function extractInlineMarker(body) {
  if (typeof body !== "string" || body.length === 0) {
    return "";
  }
  const regex = /<!--\s*identrail-reviewer:inline:([a-f0-9]{24})\s*-->/i;
  const match = regex.exec(body);
  return match ? match[1].toLowerCase() : "";
}

function inlineCommentBody(finding, markerKey) {
  const severity = String(finding.severity || "P3").toUpperCase();
  return [
    `[${severity}] ${finding.summary}`,
    `Rule: \`${finding.rule_id}\` | Confidence: ${finding.confidence}`,
    `Recommendation: ${finding.recommendation}`,
    "",
    `${INLINE_MARKER_PREFIX}${markerKey}${INLINE_MARKER_SUFFIX}`,
  ].join("\n");
}

async function upsertReviewComment({
  github,
  context,
  reviewPath,
  marker,
  heading,
  issueNumber,
  maxFindings,
  gatePath,
}) {
  if (!issueNumber || issueNumber <= 0) {
    throw new Error("issue number is required for comment upsert");
  }

  const owner = context.repo.owner;
  const repo = context.repo.repo;
  const result = JSON.parse(fs.readFileSync(reviewPath, "utf8"));
  const gate = gatePath ? JSON.parse(fs.readFileSync(gatePath, "utf8")) : undefined;
  const body = renderBody({
    marker,
    heading,
    result,
    gate,
    maxFindings,
  });

  const comments = await github.paginate(github.rest.issues.listComments, {
    owner,
    repo,
    issue_number: issueNumber,
    per_page: 100,
  });
  const existing = comments.find((comment) => comment.body && comment.body.includes(marker));
  if (existing) {
    await github.rest.issues.updateComment({
      owner,
      repo,
      comment_id: existing.id,
      body,
    });
    return;
  }

  await github.rest.issues.createComment({
    owner,
    repo,
    issue_number: issueNumber,
    body,
  });
}

async function upsertInlineReviewComments({
  github,
  context,
  reviewPath,
  changedFilesPath,
  maxComments,
}) {
  const pullRequest = context.payload.pull_request;
  if (!pullRequest || !pullRequest.number) {
    return { posted: 0, skipped: 0 };
  }

  const owner = context.repo.owner;
  const repo = context.repo.repo;
  const pullNumber = pullRequest.number;
  const commitID = pullRequest.head && pullRequest.head.sha ? pullRequest.head.sha : "";
  if (!commitID) {
    return { posted: 0, skipped: 0 };
  }

  const review = JSON.parse(fs.readFileSync(reviewPath, "utf8"));
  const findings = Array.isArray(review.findings) ? review.findings : [];
  if (findings.length === 0) {
    return { posted: 0, skipped: 0 };
  }

  const changedFiles = JSON.parse(fs.readFileSync(changedFilesPath, "utf8"));
  const touchedByPath = new Map();
  for (const file of changedFiles) {
    const normalized = normalizePath(file.filename);
    if (!normalized) {
      continue;
    }
    touchedByPath.set(normalized, parseTouchedLines(file.patch));
  }

  const existingComments = await github.paginate(github.rest.pulls.listReviewComments, {
    owner,
    repo,
    pull_number: pullNumber,
    per_page: 100,
  });
  const existingMarkers = new Set();
  for (const comment of existingComments) {
    const marker = extractInlineMarker(comment.body);
    if (marker) {
      existingMarkers.add(marker);
    }
  }

  const limit = Number.isInteger(maxComments) && maxComments > 0 ? maxComments : 10;
  let posted = 0;
  let skipped = 0;
  const seenCandidates = new Set();

  for (const finding of findings) {
    if (posted >= limit) {
      break;
    }
    const filePath = normalizePath(finding.file);
    const line = Number(finding.line);
    if (!filePath || !Number.isInteger(line) || line <= 0) {
      skipped += 1;
      continue;
    }

    const touched = touchedByPath.get(filePath);
    if (!touched || !touched.has(line)) {
      skipped += 1;
      continue;
    }

    const markerKey = findingInlineFingerprint(finding);
    if (seenCandidates.has(markerKey) || existingMarkers.has(markerKey)) {
      skipped += 1;
      continue;
    }
    seenCandidates.add(markerKey);

    try {
      await github.rest.pulls.createReviewComment({
        owner,
        repo,
        pull_number: pullNumber,
        commit_id: commitID,
        path: filePath,
        line,
        side: "RIGHT",
        body: inlineCommentBody(finding, markerKey),
      });
      posted += 1;
    } catch (error) {
      const status = error && typeof error.status === "number" ? error.status : 0;
      if (status === 422) {
        skipped += 1;
        continue;
      }
      throw error;
    }
  }

  return { posted, skipped };
}

module.exports = {
  upsertInlineReviewComments,
  upsertReviewComment,
};

