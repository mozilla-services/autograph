# Git Commit Message Best Practices

## Content Rules

The body of your commit message should provide detailed answers to the following
questions:

- What was the motivation for the change?
- How does it differ from the previous implementation?
- What effect have my changes made?
- What are the changes in reference to?
- What kind of change is it? (bugfix, refactor, feature, etc.)

Assume the reader does not understand what the commit is addressing.
They may not have access to the story addressing the detailed background of the
change, don't expect the code to be self-explanatory.

If the commit is changelog-worthy, add a "RELEASE_NOTES" tag at the bottom of
your commit, separated from your commit body by a blank line. When deciding
whether a change is noteworthy, some of these questions might help:

- Do I change the public API? -> NOTEWORTHY
- Do I change behaviour of my API? -> NOTEWORTHY
- Do I introduce a possible backwards incompatibility? -> NOTEWORTHY

## Formatting Rules

Here are some general formatting rules to follow:

- Use the imperative, present tense («change», not «changed» or «changes») to
  be consistent with generated messages from commands like git merge
- Capitalize the subject line
- Separate the subject from body line with a blank line
- Use the body to explain "what" and "why", more than "how"

## Release Notes (Changelog) Best Practices

Starting from Release v1.2, release notes for each release should be split into
an overview section and a detailed section:

- The overview section should include the main changes included in the release,
  think new features, breakages, security-impacting changes, deprecation of
  experimental features, etc.
- The detailed section should include everything else noteworthy, including but
  not limited to minor features, improvements, promotion of a feature from
  experimental to stable, etc.
