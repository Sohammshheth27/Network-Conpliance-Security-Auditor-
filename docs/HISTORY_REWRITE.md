# Git history rewrite — what changed and what teammates must do

## Why

The first commit (`a426d98`) contained a device serial number, a hostname and
site names in `.gitignore`, `reference/training_queue.jsonl` and two SonicWall
prompt files. Later commits removed them from the files, but every old version
stayed in history. `main` and `feature/extended-checks` were rewritten with
`git filter-repo` so no reachable commit contains them:

* `reference/training_queue.jsonl` removed from all history;
* the serial, hostname and site names replaced with `*-REDACTED` in every old
  file version;
* the current files are byte-identical (checked: same tree hash).

A full backup bundle of the original history was taken first
(`E:\NCSA_history_backup_<date>.bundle`).

## If you have a local clone

Your old commits no longer match GitHub's. Do NOT push them back — that would
restore the removed data.

```
git fetch origin
git checkout main
git reset --hard origin/main          # only if you have no local work on main
```

## If you have your own branch (e.g. `Tanay`)

Your branch was created from the old history, so it still contains the data.
Move only YOUR commits onto the rewritten `main`:

```
git fetch origin
git checkout Tanay
git rebase --onto origin/main a426d98 Tanay   # replays your commits only
git push --force-with-lease origin Tanay
```

Check afterwards that nothing sensitive is reachable:

```
git log origin/Tanay -i -G "<a site name>" --oneline    # should print nothing
```

## GitHub caches

Old commits can remain viewable by their SHA on GitHub for a while, and in any
pull request that referenced them. If that matters, ask GitHub Support to run
garbage collection on the repository after every branch has been updated.
