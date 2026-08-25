"use strict";

const MARKER = "<!-- codex-security-review -->";
const STALE_MARKER = "<!-- codex-security-review-stale -->";
const RISKS = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const SEVERITIES = new Set(RISKS.slice(1));
const CATEGORIES = new Set([
  "Isolation",
  "Auth",
  "Event Integrity",
  "Cryptography",
  "Injection",
  "Agent/Workflow",
  "Desktop/Mobile",
  "Concurrency",
  "Reliability",
  "Supply Chain",
  "Other",
]);

const completedMarker = (headSha) =>
  `<!-- codex-security-review-head:${headSha} -->`;

const isObject = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);

function requireKeys(value, expected, label) {
  if (!isObject(value)) {
    throw new Error(`${label} must be an object.`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    throw new Error(`${label} has unexpected or missing properties.`);
  }
}

function requireString(value, maxLength, label) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength
  ) {
    throw new Error(
      `${label} must be a non-empty string of at most ${maxLength} characters.`,
    );
  }
  return value;
}

function safeText(value, maxLength, label) {
  const input = requireString(value, maxLength, label)
    .normalize("NFKC")
    .replace(
      /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g,
      " ",
    )
    .replace(/\s+/g, " ")
    .trim();
  if (!input) {
    throw new Error(`${label} is empty after normalization.`);
  }

  return input
    .replace(/\\/g, "＼")
    .replace(/`/g, "'")
    .replace(/@/g, "＠")
    .replace(/&/g, "＆")
    .replace(/</g, "‹")
    .replace(/>/g, "›")
    .replace(/\b(https?|ftp|mailto):/gi, "$1：")
    .replace(/\bwww\./gi, "www．")
    .replace(/([*_{}\[\]()#+\-.!|])/g, "\\$1");
}

function validPath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 500 &&
    !value.startsWith("/") &&
    !value.includes("\\") &&
    !/[\u0000-\u001f\u007f]/.test(value) &&
    !value.split("/").includes("..")
  );
}

const encodePath = (value) =>
  value.split("/").map(encodeURIComponent).join("/");

async function findReviewComment({ github, context, prNumber }) {
  const comments = await github.paginate(github.rest.issues.listComments, {
    owner: context.repo.owner,
    repo: context.repo.repo,
    issue_number: prNumber,
    per_page: 100,
  });
  return comments.find(
    (comment) =>
      comment.user?.login === "github-actions[bot]" &&
      comment.user?.type === "Bot" &&
      comment.body?.startsWith(`${MARKER}\n`),
  );
}

async function upsertReviewComment({ github, context, core, prNumber, body }) {
  const existing = await findReviewComment({ github, context, prNumber });
  if (existing) {
    await github.rest.issues.updateComment({
      owner: context.repo.owner,
      repo: context.repo.repo,
      comment_id: existing.id,
      body,
    });
    core.info(`Updated Codex security review comment #${existing.id}.`);
    return;
  }

  await github.rest.issues.createComment({
    owner: context.repo.owner,
    repo: context.repo.repo,
    issue_number: prNumber,
    body,
  });
  core.info(`Posted Codex security review on PR #${prNumber}.`);
}

async function getPullRequest({ github, context, prNumber }) {
  const { data: pullRequest } = await github.rest.pulls.get({
    owner: context.repo.owner,
    repo: context.repo.repo,
    pull_number: prNumber,
  });
  if (
    pullRequest.state !== "open" ||
    pullRequest.base.repo.full_name !==
      `${context.repo.owner}/${context.repo.repo}`
  ) {
    return null;
  }
  return pullRequest;
}

async function invalidate({ github, context, core }) {
  const prNumber = Number(context.payload.pull_request?.number);
  if (!Number.isSafeInteger(prNumber) || prNumber <= 0) {
    throw new Error("Invalid pull request number for review invalidation.");
  }

  const pullRequest = await getPullRequest({ github, context, prNumber });
  if (!pullRequest) {
    core.notice(`Skipping review invalidation for closed PR #${prNumber}.`);
    return;
  }

  const existing = await findReviewComment({ github, context, prNumber });
  const currentPrefix = `${MARKER}\n${completedMarker(pullRequest.head.sha)}\n`;
  if (existing?.body?.startsWith(currentPrefix)) {
    core.info(`PR #${prNumber} already has a review for the current head.`);
    return;
  }

  const body = `${MARKER}
${STALE_MARKER}
## 🔐 Codex Security Review

> **Status: review required for the current head.**
>
> The latest external-contributor commit is \`${pullRequest.head.sha}\`.
> A Block organization member must comment exactly \`@buzz-security-review\`
> to authorize a new review. Any previous review applies only to its recorded SHA.
`;

  await upsertReviewComment({ github, context, core, prNumber, body });
}

async function post({ github, context, core }) {
  const rawReview = process.env.REVIEW_JSON || "";
  if (rawReview.length === 0 || rawReview.length > 120000) {
    throw new Error("Codex output is empty or exceeds the renderer limit.");
  }

  const review = JSON.parse(rawReview);
  requireKeys(review, ["overall_risk", "summary", "findings", "notes"], "review");
  if (!RISKS.includes(review.overall_risk)) {
    throw new Error("Review has an invalid overall risk.");
  }
  if (!Array.isArray(review.findings) || review.findings.length > 10) {
    throw new Error("Review findings must be an array with at most 10 entries.");
  }
  if (!Array.isArray(review.notes) || review.notes.length > 5) {
    throw new Error("Review notes must be an array with at most 5 entries.");
  }

  const prNumber = Number(process.env.REVIEW_PR_NUMBER);
  if (!Number.isSafeInteger(prNumber) || prNumber <= 0) {
    throw new Error("Invalid reviewed pull request number.");
  }
  const baseSha = process.env.REVIEW_BASE_SHA || "";
  const headSha = process.env.REVIEW_HEAD_SHA || "";
  const headRepo = process.env.REVIEW_HEAD_REPO || "";
  const commitRange = process.env.REVIEW_COMMIT_RANGE || "";
  if (!/^[0-9a-f]{40,64}$/.test(baseSha) || !/^[0-9a-f]{40,64}$/.test(headSha)) {
    throw new Error("Invalid reviewed commit SHA.");
  }
  if (commitRange !== `${baseSha}...${headSha}`) {
    throw new Error("Invalid reviewed commit range.");
  }
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(headRepo)) {
    throw new Error("Invalid reviewed head repository.");
  }

  const pullRequest = await getPullRequest({ github, context, prNumber });
  if (
    !pullRequest ||
    pullRequest.base.sha !== baseSha ||
    pullRequest.head.sha !== headSha ||
    pullRequest.head.repo?.full_name !== headRepo
  ) {
    core.notice(`Skipping stale review for ${commitRange} on PR #${prNumber}.`);
    return;
  }

  const files = await github.paginate(github.rest.pulls.listFiles, {
    owner: context.repo.owner,
    repo: context.repo.repo,
    pull_number: prNumber,
    per_page: 100,
  });
  if (files.length !== pullRequest.changed_files) {
    throw new Error(
      `Expected ${pullRequest.changed_files} changed files, but GitHub returned ${files.length}.`,
    );
  }
  const changedFiles = new Set(files.map((file) => file.filename));

  const findingKeys = [
    "severity",
    "category",
    "title",
    "path",
    "line",
    "description",
    "impact",
    "recommendation",
  ];
  const [headOwner, headName] = headRepo.split("/");
  const renderedFindings = review.findings.map((finding, index) => {
    const label = `finding ${index + 1}`;
    requireKeys(finding, findingKeys, label);
    if (!SEVERITIES.has(finding.severity)) {
      throw new Error(`${label} has an invalid severity.`);
    }
    if (!CATEGORIES.has(finding.category)) {
      throw new Error(`${label} has an invalid category.`);
    }
    if (!validPath(finding.path) || !changedFiles.has(finding.path)) {
      throw new Error(`${label} does not reference a changed file.`);
    }
    if (
      !Number.isSafeInteger(finding.line) ||
      finding.line < 1 ||
      finding.line > 10000000
    ) {
      throw new Error(`${label} has an invalid line number.`);
    }

    const location =
      `https://github.com/${encodeURIComponent(headOwner)}/${encodeURIComponent(headName)}` +
      `/blob/${headSha}/${encodePath(finding.path)}#L${finding.line}`;
    const pathLabel = safeText(
      `${finding.path}:${finding.line}`,
      520,
      `${label} location`,
    );
    return [
      `#### [${finding.severity}] ${safeText(finding.title, 200, `${label} title`)}`,
      `- **Category**: ${finding.category}`,
      `- **Location**: [${pathLabel}](${location})`,
      `- **Description**: ${safeText(finding.description, 1500, `${label} description`)}`,
      `- **Impact**: ${safeText(finding.impact, 1500, `${label} impact`)}`,
      `- **Recommendation**: ${safeText(finding.recommendation, 1500, `${label} recommendation`)}`,
    ].join("\n");
  });

  const highestFindingRisk = review.findings.reduce(
    (highest, finding) => Math.max(highest, RISKS.indexOf(finding.severity)),
    0,
  );
  const overallRisk = RISKS[
    Math.max(RISKS.indexOf(review.overall_risk), highestFindingRisk)
  ];
  const findingsMarkdown = renderedFindings.length
    ? renderedFindings.join("\n\n")
    : "No concrete security, correctness, or reliability findings were identified.";
  const notesMarkdown = review.notes.length
    ? review.notes
        .map((note, index) => `- ${safeText(note, 1000, `note ${index + 1}`)}`)
        .join("\n")
    : "- No additional limitations were reported.";

  const triggerActor = process.env.REVIEW_TRIGGER_ACTOR || "";
  if (!/^[A-Za-z0-9-]{1,39}$/.test(triggerActor)) {
    throw new Error("Invalid review trigger actor.");
  }
  const model = process.env.CODEX_MODEL || "";
  if (!/^[A-Za-z0-9._-]{1,100}$/.test(model)) {
    throw new Error("Invalid review model name.");
  }
  const workflowRun =
    `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}` +
    `/actions/runs/${process.env.GITHUB_RUN_ID}`;
  const body = `${MARKER}
${completedMarker(headSha)}
## 🔐 Codex Security Review

> **Note**: This is an automated, security-focused review generated by Codex.
> Use it as a supplement to human review; false positives are possible.
>
> **Scope**
> - Exact PR diff: \`${commitRange}\`
> - Model: ${model}
>
> 💡 *Click "edited" above to see earlier reviews for this PR.*

---

## Review Summary

**Overall Risk**: ${overallRisk}

${safeText(review.summary, 2000, "review summary")}

### Findings

${findingsMarkdown}

### Notes

${notesMarkdown}

---

<sub>Generated by [Codex Security Review](https://github.com/openai/codex-action) |
Requested by: \`@${triggerActor}\` |
[Workflow run](${workflowRun})</sub>`;

  if (body.length > 60000) {
    throw new Error("Rendered security review exceeds the GitHub comment limit.");
  }
  await upsertReviewComment({ github, context, core, prNumber, body });
}

module.exports = { invalidate, post };
