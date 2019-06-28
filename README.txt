README
Instructions:
Install everything in requirements.txt with "pip install -r requirements.txt" in a virutalenvironment
run command "python flaskapp.py"

pages are:
localhost:5000/toregister
localhost:5000/tologin
localhost:5000/homepage
localhost:5000/tologout

Common vulnerabilities such as sql injections are prevented against by using SQLAlchemy.
Passwords are hashed using sha256.
All forms are checked for accuracy.
Uploads can only be done when a user is logged in. This is checked through flask.
A limit is set to 100 Mb files and nothing bigger to avoid overloading server.
File uploading is checked by making sure the file is an actual png file through its extension. 
The filename is also checked using secure_filename.
File is then saved to static folder since its deemed safe. 
Image resizing follows as usual afterwards.
Image names are hashed with userid to ensure other users images wont be overwritten.
Images are stored in server and path is stored in database. This is to avoid major performance hits.
Logs are kept for all actions performed by the users and their id


CREATE TABLE member ( id int NOT NULL AUTO_INCREMENT, username VARCHAR(255), password varchar(255), first_name varchar(255), last_name varchar(255), PRIMARY KEY (id) )

CREATE TABLE images ( image_id int NOT NULL AUTO_INCREMENT, image VARCHAR(255), user_id int NOT NULL, PRIMARY KEY (image_id) )

CREATE TABLE user_actions ( action varchar(255) NOT NULL, user_id int NOT NULL, time datetime NOT NULL )

https://softwareengineering.stackexchange.com/questions/150669/is-it-a-bad-practice-to-store-large-files-10-mb-in-a-database