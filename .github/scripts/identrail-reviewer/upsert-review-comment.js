"use strict";

const fs = require("fs");

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

function renderBody({ marker, heading, result, maxFindings }) {
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const abstentions = Array.isArray(result.abstentions) ? result.abstentions : [];

  let body = `${marker}\n${heading}\n`;
  body += `Status: **${result.status}**\n\n`;
  body += `${result.summary}\n\n`;
  body += formatFindings(findings, maxFindings);
  body += formatAbstentions(abstentions);
  body += `\n_Reviewer version: ${result.version}_\n`;
  return body;
}

async function upsertReviewComment({
  github,
  context,
  reviewPath,
  marker,
  heading,
  issueNumber,
  maxFindings,
}) {
  if (!issueNumber || issueNumber <= 0) {
    throw new Error("issue number is required for comment upsert");
  }

  const owner = context.repo.owner;
  const repo = context.repo.repo;
  const result = JSON.parse(fs.readFileSync(reviewPath, "utf8"));
  const body = renderBody({
    marker,
    heading,
    result,
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

module.exports = {
  upsertReviewComment,
};
