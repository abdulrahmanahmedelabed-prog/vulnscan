"""Pull-request integrations (standard library only).

* ``github_pr``: posts one PR review with inline comments on changed lines and one summary comment, sets the job
  outcome and falls back to the job summary when the token is read-only (pull requests from forks). Used by the
  repository's composite GitHub Action (``action.yml``).
"""
