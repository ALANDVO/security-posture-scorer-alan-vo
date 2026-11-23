const core = require('@actions/core');
const github = require('@actions/github');

async function run() {
  try {
    const dbPath = core.getInput('db-path');
    const beforeScanId = core.getInput('before-scan-id');
    const afterScanId = core.getInput('after-scan-id');

    // Import the backend module - we'll use subprocess to run Python
    const { execSync } = require('child_process');
    
    // Generate the PR comment using the existing Python function
    let commentBody;
    if (beforeScanId && afterScanId) {
      commentBody = execSync(
        `cd /var/lib/alan-portfolio/workspaces/alan/security-posture-scorer-alan-vo && PYTHONPATH=. python3 -c "from backend.app.services.pr_commenter import generate_pr_comment; print(generate_pr_comment('${beforeScanId}', '${afterScanId}'))"`
      ).toString().trim();
    } else {
      // If no scan IDs provided, try to get latest scans from DB or run a scan
      // For now, post a basic status comment
      commentBody = '## 🔒 Security Posture Change Summary\n\nNo scan comparison available. Run scans with `before-scan-id` and `after-scan-id` inputs.';
    }

    // Post the comment to the pull request
    const context = github.context;
    const owner = context.repo.owner;
    const repo = context.repo.repo;
    const pullNumber = context.payload.pull_request ? context.payload.pull_request.number : null;

    if (!pullNumber) {
      core.setOutput('comment-posted', 'false');
      core.info('Not a pull request event; skipping comment post');
      return;
    }

    const octokit = github.getOctokit(process.env.GITHUB_TOKEN);
    
    // Check if a comment already exists from this bot, and if so, delete it
    const existingComments = await octokit.rest.issues.listComments({
      owner,
      repo,
      issue_number: pullNumber,
      per_page: 100
    });

    const botComment = existingComments.data.find(
      c => c.user && c.user.login === 'security-bot'
    );

    if (botComment) {
      await octokit.rest.issues.deleteComment({
        owner,
        repo,
        comment_id: botComment.id
      });
    }

    await octokit.rest.issues.createComment({
      owner,
      repo,
      issue_number: pullNumber,
      body: commentBody
    });

    core.info(`Posted security posture comment to PR #${pullNumber}`);
    core.setOutput('comment-posted', 'true');
  } catch (error) {
    core.setFailed(error.message);
  }
}

run();
