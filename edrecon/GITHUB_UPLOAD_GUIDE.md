# How to Upload EDRecon to GitHub

**A complete guide for first-time GitHub users (Windows)**

Dr. Keshav Sinha · UPES, Dehradun

---

## Before you start: what GitHub actually is

Two separate things that beginners often confuse:

| | What it is | Where it lives |
|---|---|---|
| **Git** | Software that tracks file changes | On your laptop |
| **GitHub** | A website that stores Git projects online | In the cloud |

**The mistake you already hit:** `git remote add origin <url>` does *not* create
anything on GitHub. It only writes that URL into a config file on your laptop.
You must create the repository on the GitHub website first, by hand. Git has no
way to create it for you.

Think of it like this: `git remote add` is writing an address on an envelope.
It does not build the house at that address.

---

## Part 1 — Create your GitHub account

Skip if you already have one.

1. Go to **https://github.com/signup**
2. Enter your email — use a personal address, not only your institutional one,
   so you keep the account if you ever change employer
3. Choose a password and a username

   > Your username becomes part of every URL: `github.com/<username>/edrecon`.
   > Pick something professional and permanent — `keshavsinha` or
   > `drkeshavsinha`. It is awkward to change later.

4. Verify your email — GitHub sends a code
5. Choose the **Free** plan; it includes unlimited public and private repositories

### Find your exact username

This matters, because it must match your URL exactly.

1. Sign in at github.com
2. Click your **avatar** (top-right corner)
3. Click **Your profile**
4. Look at the browser address bar: `https://github.com/XXXXXXX`

That `XXXXXXX` is your username. Write it down.

---

## Part 2 — Create the repository on GitHub

**This is the step that was missing.**

1. Sign in at github.com
2. Click the **`+`** icon in the top-right corner
3. Click **New repository**
4. Fill the form:

   | Field | What to enter |
   |---|---|
   | **Repository name** | `edrecon` — lowercase, no spaces |
   | **Description** | `Explainable reconnaissance framework for security education` |
   | **Public / Private** | Your choice (see note below) |
   | **Add a README file** | **Leave unticked** |
   | **Add .gitignore** | **Leave unticked — None** |
   | **Choose a license** | **Leave unticked — None** |

   > **Why leave the three boxes unticked?** You already have a README,
   > .gitignore and LICENSE in your folder. If GitHub also creates them, you
   > get two conflicting starting points and your first push is rejected with
   > a confusing "rejected — fetch first" error.

   > **Public or Private?** Public means anyone can see and download it — this
   > is what you want for academic credit and student access. Private means
   > only you and people you invite. You can switch Public later, but you
   > cannot un-publish something people have already cloned. If you are unsure,
   > start Private and flip to Public when you are ready.

5. Click the green **Create repository** button

You will land on a page headed *"Quick setup — if you've done this kind of
thing before"*. **If you see this page, the repository now exists.** That page
is proof.

Keep it open — you will need the URL from it.

---

## Part 3 — Get the files onto your computer

1. Download `edrecon.zip`
2. Right-click it → **Extract All…**
3. Extract to a simple path with **no spaces and no brackets**, for example:

   ```
   C:\Users\keshav.sinha\edrecon
   ```

   > **Important:** your current path is `E:\files (10)\edrecon`. The space and
   > the brackets in `files (10)` will cause problems in Git Bash — you have to
   > escape them constantly. Move the folder somewhere simple before starting.
   > This will save you real frustration.

4. Open the extracted folder. You should see `edrecon.py`, `README.md`,
   a `core` folder, a `modules` folder, and so on. If instead you see a single
   folder named `edrecon` containing all of that, go one level deeper — you
   want the folder that *directly contains* `edrecon.py`.

---

## Part 4 — Upload

Two methods. **Method A needs no commands at all.** Use it if you just want
the code online today. Method B is the proper way and is worth learning, but
it has more places to trip.

---

### METHOD A — Upload through the website (easiest)

No Git, no terminal, no tokens.

1. On your new empty repository page on GitHub, click the link
   **uploading an existing file** (in the text *"…or upload an existing file"*)
2. Open your `edrecon` folder in Windows Explorer
3. Select **everything** — press `Ctrl+A`
4. **Drag** the selected files into the GitHub upload area in your browser
5. Wait for all files to finish uploading (folders are preserved automatically)
6. Scroll down to **Commit changes**
7. In the first box type: `EDRecon v1.0.0 - initial release`
8. Click **Commit changes**

Done. Your code is live at `github.com/<username>/edrecon`.

> **One catch:** Windows Explorer hides files starting with a dot, so
> **`.gitignore` will not be uploaded** by drag-and-drop. Add it manually:
> on your repository page click **Add file → Create new file**, name it
> exactly `.gitignore`, paste in the contents from your local copy (open it
> with Notepad), and commit. This file matters — it is what stops you
> accidentally publishing scan reports and real scope files later.

---

### METHOD B — Upload with Git Bash (the proper way)

Use this if you want to push updates easily in future.

#### B1. Install Git

If `git` is not recognised, download from **https://git-scm.com/download/win**
and install with all default options. Then right-click inside your `edrecon`
folder → **Open Git Bash here**.

#### B2. Tell Git who you are

One time only, on this laptop:

```bash
git config --global user.name "Keshav Sinha"
git config --global user.email "your-github-email@example.com"
```

Use the same email as your GitHub account, otherwise your commits will not be
linked to your profile.

#### B3. Navigate to the folder

```bash
cd ~/edrecon
pwd
ls
```

`ls` must show `edrecon.py`, `README.md`, `core`, `modules`. If it does not,
you are in the wrong folder.

#### B4. Start tracking and commit

```bash
git init
git branch -M main
git add .
git status
```

**Stop and read the `git status` output carefully.** You should see about 34
files. You must **not** see:

- `scope.yaml` (your real scope file — contains target IPs)
- anything inside `reports/` (scan results)
- `.venv/` (hundreds of library files)

If any of those appear, `.gitignore` was not extracted. Fix that before
continuing — data pushed to a public repository is very hard to remove from
history.

Then commit:

```bash
git commit -m "EDRecon v1.0.0 - explainable reconnaissance framework"
```

#### B5. Connect to GitHub and push

Replace `<username>` with your actual GitHub username:

```bash
git remote add origin https://github.com/<username>/edrecon.git
git remote -v
git push -u origin main
```

`git remote -v` prints the URL back. **Check the spelling of your username.**

#### B6. Sign in when prompted

A browser window should open asking you to authorise Git Credential Manager.
Sign in and approve. It remembers you afterwards.

If instead the terminal asks for a **password**, do not type your GitHub
password — it will not work. You need a token:

1. GitHub → your avatar → **Settings**
2. Scroll to the bottom → **Developer settings**
3. **Personal access tokens** → **Fine-grained tokens** → **Generate new token**
4. Name: `laptop`. Expiration: 90 days
5. **Repository access** → *Only select repositories* → choose `edrecon`
6. **Permissions** → *Repository permissions* → **Contents** → set to
   **Read and write**
7. **Generate token**, then **copy it immediately** — it is shown only once
8. Paste the token where the terminal asks for a password
   (nothing appears as you paste; that is normal — press Enter)

---

## Part 5 — Confirm it worked

Visit `https://github.com/<username>/edrecon` in your browser.

You should see your files, and the README rendered underneath with the badges
and the sample finding output.

---

## Part 6 — Finishing touches

### Add topics so people can find it

On your repository page, click the **gear icon** next to *About* (right-hand
side) and add topics:

```
security-education   reconnaissance   ethical-hacking
osint   python   cybersecurity   teaching-tool
```

Also set the **Website** field to `https://edcatalyst.in`.

### Create a release with the PDF attached

This gives people a versioned download without cloning.

1. On your repository page, click **Releases** (right-hand side) →
   **Create a new release**
2. Click **Choose a tag** → type `v1.0.0` → **Create new tag**
3. Release title: `EDRecon v1.0.0`
4. Description: a short summary of what the tool does
5. Drag `EDRecon_Complete_Documentation.pdf` into the attachments box
6. Click **Publish release**

---

## Part 7 — Making changes later

This is the everyday cycle once the repository exists. Only three commands.

```bash
cd ~/edrecon

# 1. Stage everything you changed
git add .

# 2. Save a snapshot with a message describing the change
git commit -m "Add SNMP knowledge base entries"

# 3. Send it to GitHub
git push
```

That is the whole routine. After the first `push -u origin main`, plain
`git push` is enough.

### Useful checks

```bash
git status              # what has changed since the last commit
git log --oneline       # history of your commits
git diff                # exactly what changed, line by line
git remote -v           # which GitHub repository you are connected to
```

### Editing a file directly on GitHub

For a quick typo fix you do not need Git at all: open the file on GitHub,
click the **pencil icon**, edit, and click **Commit changes**. Then on your
laptop run `git pull` to bring that change down before making further local
edits.

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `Repository not found` | Repository not created on the website | Do Part 2 |
| `Repository not found` (it does exist) | Username misspelled in the URL | `git remote set-url origin https://github.com/<correct>/edrecon.git` |
| `remote origin already exists` | You ran `git remote add` twice | `git remote set-url origin <url>` instead |
| `Updates were rejected` / `fetch first` | You ticked README/licence when creating the repo | `git pull origin main --allow-unrelated-histories` then push again |
| `Authentication failed` | Used your password, not a token | Create a token — see B6 |
| `src refspec main does not match any` | Nothing has been committed yet | Run `git add .` then `git commit -m "..."` |
| `does not have any commits yet` | Same as above | Same as above |
| `Permission denied` | Signed into the wrong GitHub account | Windows: Credential Manager → remove the GitHub entry, push again |
| `fatal: not a git repository` | You are in the wrong folder | `cd` to the folder containing `edrecon.py`, run `git init` |

### If you accidentally commit a scope file or scan report

Do not just delete it and commit again — it stays in the history.

```bash
git rm --cached scope.yaml
echo "scope.yaml" >> .gitignore
git commit -m "Remove scope file from tracking"
git push
```

This stops it being tracked going forward, but **the old version remains in
the repository history and is still visible**. If the file contained anything
genuinely sensitive, the safest course is to delete the repository on GitHub
(Settings → scroll to the bottom → Delete this repository) and start over with
a clean `git init`. That is why the `git status` check in step B4 matters.

---

## Quick reference card

**One-time setup**

```bash
git config --global user.name "Keshav Sinha"
git config --global user.email "you@example.com"
```

**First upload** (repository must already exist on github.com)

```bash
cd ~/edrecon
git init
git branch -M main
git add .
git status                    # CHECK: no scope.yaml, no reports/
git commit -m "EDRecon v1.0.0"
git remote add origin https://github.com/<username>/edrecon.git
git push -u origin main
```

**Every update after that**

```bash
git add .
git commit -m "what you changed"
git push
```

---

*EDRecon — an EDCatalyst teaching tool.*
*Dr. Keshav Sinha, UPES, Dehradun, India.*
