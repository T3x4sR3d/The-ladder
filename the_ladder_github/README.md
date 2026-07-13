# THE LADDER

A Flask + SQLite proof-of-concept for club shooting ladders and New Zealand ranking records.

## Included in this GitHub version

- Empty SQLite database except for the default super admin account.
- Super admin password-change form on the Admin page.
- Club admin accounts can be created by the super admin.
- Shooter accounts can be registered by club admins.
- New Zealand Rankings are separate from ladder scores.
- Sanctioned ranking scores can only be entered by the super admin.
- Club weekly ladder scores do not affect ranking scores.
- Optional New Zealand Ladder can be toggled on/off by the super admin.
- Club ladders remain available to clubs.
- Local network hosting support for testing on a phone.

## Default login

```text
Username: superadmin
Password: change-me-now
```

Change this immediately after first login using **Admin → Change Super Admin Password**.

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Run on local Wi-Fi

```bash
python3 app.py --host 0.0.0.0
hostname -I
```

Then open on your phone:

```text
http://YOUR-LAPTOP-IP:5000
```

## Database

This version includes `ladder.db` with only the super admin account. No clubs, shooters, scores, ranking scores, or dummy data are included.

To reset the database:

```bash
rm ladder.db
python3 app.py
```

The app will recreate an empty database with only the default super admin.

## Security notes

This is still a proof-of-concept. Before real deployment, set a long secret key before first database creation:

```bash
export LADDER_SECRET_KEY='replace-this-with-a-long-random-secret'
```

Do not commit real production data or real user passwords to GitHub.
