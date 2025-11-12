# How to Change the Default Branch to `copilot/improve-pentesting-agent-llms`

This document provides instructions for changing the default branch of the Aegis_agent repository to `copilot/improve-pentesting-agent-llms`.

## Why This Can't Be Done Through Code

Changing a repository's default branch is a **repository setting** on GitHub that requires administrative access to the repository. This cannot be accomplished through:
- Git commands in the repository
- Code changes or commits
- Pull requests

## Methods to Change the Default Branch

### Method 1: Using GitHub Web Interface (Recommended)

1. **Navigate to Repository Settings**
   - Go to https://github.com/Yahya-hacker/Aegis_agent
   - Click on **Settings** (you need admin/owner permissions)

2. **Access Branches Settings**
   - In the left sidebar, click on **Branches**
   - You'll see the "Default branch" section at the top

3. **Change the Default Branch**
   - Click the switch/pencil icon next to the current default branch
   - In the dropdown, select `copilot/improve-pentesting-agent-llms`
   - Click **Update** or **I understand, update the default branch**

4. **Confirm the Change**
   - GitHub will show a confirmation dialog explaining the implications
   - Confirm the change

### Method 2: Using GitHub CLI (gh)

If you have the GitHub CLI installed and authenticated:

```bash
# Switch to the desired default branch
gh api repos/Yahya-hacker/Aegis_agent -X PATCH -f default_branch='copilot/improve-pentesting-agent-llms'
```

### Method 3: Using GitHub API with curl

If you have a personal access token with `repo` scope:

```bash
curl -X PATCH \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer YOUR_GITHUB_TOKEN" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/Yahya-hacker/Aegis_agent \
  -d '{"default_branch":"copilot/improve-pentesting-agent-llms"}'
```

## What Happens When You Change the Default Branch

When you change the default branch:

1. **New clones** will check out the new default branch automatically
2. **Pull requests** will target the new default branch by default
3. **GitHub Pages** (if enabled) may be affected
4. **Branch protection rules** may need to be adjusted
5. **Existing clones** are NOT affected - developers need to update their local repos

## After Changing the Default Branch

Users with existing clones should update their local repositories:

```bash
# Fetch the latest changes
git fetch origin

# Switch to the new default branch
git checkout copilot/improve-pentesting-agent-llms

# Set it as the tracking branch
git branch -u origin/copilot/improve-pentesting-agent-llms

# Optional: Update the local main/master branch reference
git symbolic-ref refs/remotes/origin/HEAD refs/remotes/origin/copilot/improve-pentesting-agent-llms
```

## Verification

After changing the default branch, verify the change by:

1. Visiting https://github.com/Yahya-hacker/Aegis_agent (should show the new branch)
2. Creating a new repository clone and checking which branch is checked out
3. Running: `git ls-remote --symref origin HEAD`

## Important Considerations

- **Permissions Required**: You need admin or owner permissions on the repository
- **Impact on PRs**: Open pull requests targeting the old default branch will still target it (they won't automatically retarget)
- **CI/CD**: Check if any CI/CD pipelines reference the old default branch name
- **Documentation**: Update any documentation that references the old default branch
- **Protected Branches**: Consider applying the same protection rules to the new default branch

## Branch Information

- **Target Branch**: `copilot/improve-pentesting-agent-llms`
- **Branch SHA**: `5299a172ef835747f6d344dd74581be4d7727fc1`
- **Current Default**: Likely `main`
