---
layout: post
title: "Intermediate GIT"
subtitle: 
cover_image: 
excerpt: "Intermediate usage of git, on `add`, `rebase`, `reset`, `fetch` and `cherry-pick`"
category: 
tags: [git]
thumbnail: "/tb/git.png"
---

### git add

__Scenario #1__: I made changes on one file, I want to commit several changes in one file, and left the other changes for next commit.

`git add -p`: add patch. Add by change.

__Scenario #2__: I made changes on several files, I want to commit some files, and left the other files for next commit.

`git add -i`: better than `-p`. Add by file. Can split patch by using `s` command

### git rebase

Git rebase: forward-port local commits to the updated upstream head.

__Scenario #3__: I'm developing, the remote branch changed. I want to add the remote changes to my developing branch, without creating the merge commit.

`git pull --rebase`

__Scenario #4__: I want to merge some previous commits, since they are related to the same feature.

`git rebase -i`: interactive. Used to merge multiple commits. Can `squash`, and `pick`.

* `git rebase -i HEAD~5`: 5 versions before `HEAD`
* `git rebase -i HEAD^^^^^`

### git reset

* `hard`: clean index, clean cached file
* `mixed`: clean index, keep cached file
* `soft`: keep index, keep cached file

__Scenario #5__: Same as __Scenario #4__: 

	git reset --mixed <commit id>
	git commit	

`--mixed` can also be used to merge multiple commits. `git rebase -i` is another way.

To check cached file, use `git diff --cached`

### git fetch

__Scenario #6__: Get remote changes, but not merge into local branch.

	git fetch
	
To merge, the workflow is:

	git fetch origin
	git rebase origin/master
	
Which is equivalent to
	
	git pull --rebase
	
### git cherry-pick

Definition: merge a single commit from another branch to local branch

__Scenario #7__: I developed v3.0. I want to merge some stable feature of v3.0 to v2.0.

	# suppose the new feature commit id is f79b0b1ffe445cab6e531260743fa4e08fb4048b
	git co v2.0
	git cherry-pick f79b0b1	
