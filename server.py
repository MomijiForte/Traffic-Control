#!/usr/bin/env python

# This is a simple web server for a traffic counting application.
# It's your job to extend it by adding the backend functionality to support
# recording the traffic in a SQL database. You will also need to support
# some predefined users and access/session control. You should only
# need to extend this file. The client side code (html, javascript and css)
# is complete and does not require editing or detailed understanding.

# import the various libraries needed
import http.cookies as Cookie
from itertools import count, filterfalse
from os import access  # some cookie handling support
import random
import string
from http.server import BaseHTTPRequestHandler, HTTPServer  # the heavy lifting of the web server
import urllib  # some url parsing support
import json  # support for json encoding
import sys  # needed for agument handling
import sqlite3
import time
import re
import datetime

# file = 'db/clean.db'
file = 'traffic.db'

# connect to database
def access_database(db_file, query, var = ()):
    connect = sqlite3.connect(db_file)
    cursor = connect.cursor()
    if len(var) > 0:
        cursor.execute(query, var)
    else:
        cursor.execute(query)
    connect.commit()
    connect.close()

def access_database_with_results(db_file, query, var = ()):
    connect = sqlite3.connect(db_file)
    cursor = connect.cursor()
    if len(var) > 0:
        rows = cursor.execute(query, var).fetchall()
    else:
        rows = cursor.execute(query).fetchall()
    connect.commit()
    connect.close()
    return rows

def setup_assessment_tables(dbfile):
    # Get rid of any existing data
    access_database(dbfile, "DROP TABLE IF EXISTS users")
    access_database(dbfile, "DROP TABLE IF EXISTS session")
    access_database(dbfile, "DROP TABLE IF EXISTS traffic")
    
    access_database(dbfile, "CREATE TABLE users (userid INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    access_database(dbfile, "CREATE TABLE session (sessionid INTEGER PRIMARY KEY, userid INTEGER, magic TEXT, start INTEGER, end INTEGER)")
    access_database(dbfile, "CREATE TABLE traffic (recordid INTEGER PRIMARY KEY, sessionid INTEGER, time INTEGER, type INTEGER, occupancy INTEGER, location TEXT, mode INTEGER)")
    access_database(dbfile, "INSERT INTO users VALUES (1,'test1','password1'), (2,'test2','password2'), (3,'test3','password3'), (4,'test4','password4'), (5,'test5','password5'), (6,'test6','password6'), (7,'test7','password7'), (8,'test8','password8'), (9,'test9','password9'), (10,'test10','password10')")
setup_assessment_tables(file)

def build_response_refill(where, what):
    """This function builds a refill action that allows part of the
       currently loaded page to be replaced."""
    return {"type": "refill", "where": where, "what": what}


def build_response_redirect(where):
    """This function builds the page redirection action
       It indicates which page the client should fetch.
       If this action is used, only one instance of it should
       contained in the response and there should be no refill action."""
    return {"type": "redirect", "where": where}


def handle_validate(iuser, imagic):
    """Decide if the combination of user and magic is valid"""

    query = access_database_with_results(file, "SELECT users.username, session.magic FROM users INNER JOIN session ON users.userid = session.userid WHERE users.username= ? AND session.magic= ? AND session.end=0", (iuser, imagic,))
    query_new = [list(text) for text in query]
    for i in range(len(query_new)):
        if (iuser == query[i][0]) or (imagic == query[i][1]):
            return True
        else:
            return False

def handle_delete_session(iuser, imagic):
    """Remove the combination of user and magic from the data base, ending the login"""
    end = int(time.time())
    query = access_database_with_results(file, "SELECT userid from users WHERE username= ?", (iuser,))
    userid = query[0][0] 
    access_database(file, "UPDATE session SET magic ='' , end= ? where userid= ?", (end, userid,))
    return

def handle_login_request(iuser, imagic, parameters):
    """A user has supplied a username (parameters['usernameinput'][0])
       and password (parameters['passwordinput'][0]) check if these are
       valid and if so, create a suitable session record in the database
       with a random magic identifier that is returned.
       Return the username, magic identifier and the response action set."""

    user = ''
    magic = ''
    response = []

    if "usernameinput" not in parameters.keys() or "passwordinput" not in parameters.keys():
        response.append(build_response_refill('message', 'Please enter valid username and password'))
        return [user, magic, response]

    username = parameters['usernameinput'][0]
    userpass = parameters['passwordinput'][0]

    row = access_database_with_results(file, "SELECT * from users")
    flag = 0
    for i in range(10):
        if username == row[i][1] and userpass == row[i][2]:

            login_check = access_database_with_results(file, "select userid, username from users where username = ? and password = ? ", (username, userpass,))            
            if len(login_check) > 0:
                u_id = login_check[0][0]
                iuser = login_check[0][1]

            token = access_database_with_results(file, "SELECT magic from session where userid = ? order by sessionid DESC limit 1", (u_id,))
            if len(token) > 0:
                magic_new = token[0][0]
            else:
                magic_new = 0

            if handle_validate(iuser, magic_new) == True:
                # the user is already logged in, so end the existing session.
                handle_delete_session(iuser, magic_new)

            magic_token = ''.join(random.choices(string.ascii_letters + string.digits, k=36))
            start = int(time.time())
            user_id = login_check[0][0]
            user = login_check[0][1]
            magic = magic_token
            access_database(file, "INSERT into session (userid, magic, start, end) values (?, ?, ?, 0)", (user_id, magic_token, start,))
            
            flag = 1
            response.append(build_response_redirect('/page.html'))
            return [user, magic, response]
    # alter as required

    if flag == 0:  # The user is not valid
        # user = ''
        # magic = ''
        response.append(build_response_refill('message', 'Invalid username or password'))
        user = '!'
        magic = ''
        return [user, magic, response]

def change(type_1):
    vehicles =  {"car": 0, "van":1, "truck":2, "taxi":3, "other":4, "motorbike":5, "bicycle":6, "bus":7}
    if type_1 not in vehicles.keys():
        vehicles_values = 10
    else:
        vehicles_values = vehicles[type_1]
    return vehicles_values

def handle_add_request(iuser, imagic, parameters):
    """The user has requested a vehicle be added to the count
       parameters['locationinput'][0] the location to be recorded
       parameters['occupancyinput'][0] the occupant count to be recorded
       parameters['typeinput'][0] the type to be recorded
       Return the username, magic identifier (these can be empty  strings) and the response action set."""
    response = []
    user = iuser
    magic = imagic
    ## alter as required

    if handle_validate(iuser, imagic) != True:
    # Invalid sessions redirect to login
        response.append(build_response_redirect('/index.html'))
        return [user, magic, response]
    else:  # a valid session so process the addition of the entry.
        if "locationinput" not in parameters.keys():
            response.append(build_response_refill('message', 'Please enter a location'))
            return [user, magic, response]
        
        location = parameters['locationinput'][0]
        occupancy = parameters['occupancyinput'][0]
        type_add = parameters['typeinput'][0]
        now = int(time.time())

        if location != " ".join(re.findall(r"[a-z0-9A-Z]+", location)):
            response.append(build_response_refill('message', 'No special characters Please get rid of it'))
            return [user, magic, response]

        else:

            vehicles_values = change(type_add)
            if vehicles_values == 10:
                response.append(build_response_refill('message', 'Invalid Type'))
                return [iuser, imagic, response]

            sessionid_check = access_database_with_results(file, "SELECT sessionid from session where magic = ?", (imagic,))
            sessionid = sessionid_check[0][0]
        
            access_database(file, "INSERT INTO traffic (sessionid, time, type, occupancy, location, mode) values (?, ?, ?, ?, ?, 1)", (sessionid, now, vehicles_values, occupancy, location,))
            response.append(build_response_refill('message', 'Entry added.'))

            count_num = access_database_with_results(file, "SELECT count(mode) from traffic where mode = 1 and sessionid = ?", (sessionid,))
            if len(count_num) > 0:
                count = count_num[0][0]
            else:
                count = 0
                response.append(build_response_refill('message', 'NO entry added'))
                
            response.append(build_response_refill('total', str(count)))
            return [user, magic, response]


def handle_undo_request(iuser, imagic, parameters):
    """The user has requested a vehicle be removed from the count
       This is intended to allow counters to correct errors.
       parameters['locationinput'][0] the location to be recorded
       parameters['occupancyinput'][0] the occupant count to be recorded
       parameters['typeinput'][0] the type to be recorded
       Return the username, magic identifier (these can be empty  strings) and the response action set."""
    response = []
    user = iuser
    magic = imagic
    # alter as required

    location = parameters['locationinput'][0]
    occupancy = parameters['occupancyinput'][0]
    type_undo = parameters['typeinput'][0]
    now = int(time.time())

    if handle_validate(iuser, imagic) != True:
        # Invalid sessions redirect to login
        response.append(build_response_redirect('/index.html'))
        return [user, magic, response]
    else:  # a valid session so process the recording of the entry.
        if "locationinput" not in parameters.keys():
            response.append(build_response_refill('message', 'Please enter a location'))
            return [user, magic, response]
        
        elif location != " ".join(re.findall(r"[a-z0-9A-Z]+", location)):
            response.append(build_response_refill('message', 'No special characters Please get rid of it'))
            return [user, magic, response]

        vehicles_values = change(type_undo)
        if vehicles_values == 10:
            response.append(build_response_refill('message', 'Invalid Type'))
            return [iuser, imagic, response]

        sessionid_check = access_database_with_results(file, "SELECT sessionid from session where magic = ?", (imagic,))
        sessionid = sessionid_check[0][0]

        access_database_with_results(file, "UPDATE traffic set mode = 2 where sessionid = ? and type = ? and occupancy = ? and location = ?", (sessionid, vehicles_values, occupancy, location,))

        recordid = access_database_with_results(file, "SELECT * from traffic where sessionid = ? and type = ? and occupancy = ? and location = ?", (sessionid, vehicles_values, occupancy, location,))[0][0]
        access_database('traffic.db', f" INSERT INTO traffic (sessionid , [time] , [type], occupancy, [location], mode) select sessionid , [time] , [type], occupancy, [location],0 from traffic where recordid = '{recordid}' ")
        
        response.append(build_response_refill('message', 'Undo Entry Success.'))

        count_num = access_database_with_results(file, "SELECT count(mode) from traffic where mode = 1 and sessionid = ?", (sessionid,))
        if len(count_num) > 0:
            count = count_num[0][0]
        else:
            count = 0
            response.append(build_response_refill('message', 'NO Such entry, Undo failed. Please Check location, occupancy and type.'))
            return [user, magic, response]
        
        response.append(build_response_refill('total', str(count)))
        return [user, magic, response]


def handle_back_request(iuser, imagic, parameters):
    """This code handles the selection of the back button on the record form (page.html)
       You will only need to modify this code if you make changes elsewhere that break its behaviour"""
    response = []
    # alter as required
    if handle_validate(iuser, imagic) != True:
        response.append(build_response_redirect('/index.html'))
    else:
        response.append(build_response_redirect('/summary.html'))
    user = iuser # ''
    magic = imagic # ''
    return [user, magic, response]


def handle_logout_request(iuser, imagic, parameters):
    """This code handles the selection of the logout button on the summary page (summary.html)
       You will need to ensure the end of the session is recorded in the database
       And that the session magic is revoked."""
    response = []
    now = int(time.time())
    access_database(file, "UPDATE [session] set magic = 'None', end = ? where userid = ?", (now, iuser,))
    # alter as required
    response.append(build_response_redirect('/index.html'))
    user = iuser
    magic = imagic
    return [user, magic, response]

def handle_summary_request(iuser, imagic, parameters):
    """This code handles a request for an update to the session summary values.
       You will need to extract this information from the database.
       You must return a value for all vehicle types, even when it's zero."""
    response = []
    user = iuser
    magic = imagic
    ## alter as required
    if handle_validate(iuser, imagic) != True:
        response.append(build_response_redirect('/index.html'))
    else:
        userid = access_database_with_results(file, "SELECT distinct userid from users where username = ?", (iuser,))[0][0]
        sessionid = access_database_with_results(file, "SELECT sessionid from session where userid = ? and magic = ?", (userid, imagic,))[0][0]
        car = access_database_with_results(file, "SELECT count(mode) from traffic where sessionid = ? and mode = 1 and type = 0", (sessionid,))
        taxi = access_database_with_results(file, "SELECT count(mode) from traffic where sessionid = ? and mode = 1 and type = 3", (sessionid,))
        bus = access_database_with_results(file, "SELECT count(mode) from traffic where sessionid = ? and mode = 1 and type = 7", (sessionid,))
        motorbike = access_database_with_results(file, "SELECT count(mode) from traffic where sessionid = ? and mode = 1 and type = 5", (sessionid,))        
        bicycle = access_database_with_results(file, "SELECT count(mode) from traffic where sessionid = ? and mode = 1 and type = 6", (sessionid,))
        van = access_database_with_results(file, "SELECT count(mode) from traffic where sessionid = ? and mode = 1 and type = 1", (sessionid,))
        truck = access_database_with_results(file, "SELECT count(mode) from traffic where sessionid = ? and mode = 1 and type = 2", (sessionid,))
        other = access_database_with_results(file, "SELECT count(mode) from traffic where sessionid = ? and mode = 1 and type = 4", (sessionid,))
        total = access_database_with_results(file, "SELECT count(mode) from traffic where sessionid = ? and mode = 1", (sessionid,))

        response.append(build_response_refill('sum_car', car[0][0]))
        response.append(build_response_refill('sum_taxi', taxi[0][0]))
        response.append(build_response_refill('sum_bus', bus[0][0]))
        response.append(build_response_refill('sum_motorbike', motorbike[0][0]))
        response.append(build_response_refill('sum_bicycle', bicycle[0][0]))
        response.append(build_response_refill('sum_van', van[0][0]))
        response.append(build_response_refill('sum_truck', truck[0][0]))
        response.append(build_response_refill('sum_other', other[0][0]))
        response.append(build_response_refill('total', total[0][0]))  

    return [user, magic, response]

# HTTPRequestHandler class
class myHTTPServer_RequestHandler(BaseHTTPRequestHandler):

    # GET This function responds to GET requests to the web server.
    def do_GET(self):

        # The set_cookies function adds/updates two cookies returned with a webpage.
        # These identify the user who is logged in. The first parameter identifies the user
        # and the second should be used to verify the login session.
        def set_cookies(x, user, magic):
            ucookie = Cookie.SimpleCookie()
            ucookie['u_cookie'] = user
            x.send_header("Set-Cookie", ucookie.output(header='', sep=''))
            mcookie = Cookie.SimpleCookie()
            mcookie['m_cookie'] = magic
            x.send_header("Set-Cookie", mcookie.output(header='', sep=''))

        # The get_cookies function returns the values of the user and magic cookies if they exist
        # it returns empty strings if they do not.
        def get_cookies(source):
            rcookies = Cookie.SimpleCookie(source.headers.get('Cookie'))
            user = ''
            magic = ''
            for keyc, valuec in rcookies.items():
                if keyc == 'u_cookie':
                    user = valuec.value
                if keyc == 'm_cookie':
                    magic = valuec.value
            return [user, magic]

        # Fetch the cookies that arrived with the GET request
        # The identify the user session.
        user_magic = get_cookies(self)

        print(user_magic)

        # Parse the GET request to identify the file requested and the parameters
        parsed_path = urllib.parse.urlparse(self.path)

        # Decided what to do based on the file requested.

        # Return a CSS (Cascading Style Sheet) file.
        # These tell the web client how the page should appear.
        if self.path.startswith('/css'):
            self.send_response(200)
            self.send_header('Content-type', 'text/css')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return a Javascript file.
        # These tell contain code that the web client can execute.
        elif self.path.startswith('/js'):
            self.send_response(200)
            self.send_header('Content-type', 'text/js')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # A special case of '/' means return the index.html (homepage)
        # of a website
        elif parsed_path.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('./index.html', 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return html pages.
        elif parsed_path.path.endswith('.html'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('.'+parsed_path.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # The special file 'action' is not a real file, it indicates an action
        # we wish the server to execute.
        elif parsed_path.path == '/action':
            self.send_response(200) #respond that this is a valid page request
            # extract the parameters from the GET request.
            # These are passed to the handlers.
            parameters = urllib.parse.parse_qs(parsed_path.query)

            if 'command' in parameters:
                # check if one of the parameters was 'command'
                # If it is, identify which command and call the appropriate handler function.
                if parameters['command'][0] == 'login':
                    [user, magic, response] = handle_login_request(user_magic[0], user_magic[1], parameters)
                    #The result of a login attempt will be to set the cookies to identify the session.
                    set_cookies(self, user, magic)
                elif parameters['command'][0] == 'add':
                    [user, magic, response] = handle_add_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'undo':
                    [user, magic, response] = handle_undo_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'back':
                    [user, magic, response] = handle_back_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'summary':
                    [user, magic, response] = handle_summary_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'logout':
                    [user, magic, response] = handle_logout_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                else:
                    # The command was not recognised, report that to the user.
                    response = []
                    response.append(build_response_refill('message', 'Internal Error: Command not recognised.'))

            else:
                # There was no command present, report that to the user.
                response = []
                response.append(build_response_refill('message', 'Internal Error: Command not found.'))

            text = json.dumps(response)
            print(text)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(text, 'utf-8'))

        elif self.path.endswith('/statistics/hours.csv'):
            ## if we get here, the user is looking for a statistics file
            ## this is where requests for /statistics/hours.csv should be handled.
            ## you should check a valid user is logged in. You are encouraged to wrap this behavour in a function.
            response = []
            iuser = user_magic[0]
            imagic = user_magic[1]
            if handle_validate(iuser, imagic) != True:
                response.append(build_response_redirect("/index.html"))
            else:
                max_timing = access_database_with_results('traffic.db', "SELECT max(time) from traffic where mode = 1")[0][0]

                day_sec = int(86400)
                day_ago = int(max_timing - day_sec)
                
                week_sec = int(604800)
                week_ago = int(max_timing - week_sec)
                
                month_sec = int(2628000)
                month_ago = int(max_timing - month_sec)

                day_count = access_database_with_results('traffic.db', f"SELECT users.username, SUM(session.end - session.start) FROM session join users on users.userid = session.userid where (session.start < {max_timing}) and (session.end > {day_ago}) and session.end > 0 group by users.username")
                week_count = access_database_with_results('traffic.db', "SELECT users.username, SUM(session.end - session.start) FROM session join users on users.userid = session.userid where session.end > 0 and (session.start < ?) and (session.end > ?) group by users.username", (max_timing, week_ago,))
                month_count = access_database_with_results('traffic.db', "SELECT users.username, SUM(session.end - session.start) FROM session join users on users.userid = session.userid where session.end > 0 and (session.start < ?) and (session.end > ?) group by users.username", (max_timing, month_ago,))

                text = "Username,Day,Week,Month\n"
                for i in range(len(day_count)):
                    users = day_count[i][0]
                    day_worked = round(day_count[i][1]/(3600),1)
                    week_worked = round(week_count[i][1]/(3600),1)
                    month_worked = round(month_count[i][1]/(3600),1)
                    text+= f"{users},{day_worked},{week_worked},{month_worked}\n"
                    

            encoded = bytes(text, 'utf-8')
            self.send_response(200)
            self.send_header('Content-type', 'text/csv')
            self.send_header("Content-Disposition", 'attachment; filename="{}"'.format('hours.csv'))
            self.send_header("Content-Length", len(encoded))
            self.end_headers()
            self.wfile.write(encoded)

        elif self.path.endswith('/statistics/traffic.csv'):
            ## if we get here, the user is looking for a statistics file
            ## this is where requests for  /statistics/traffic.csv should be handled.
            ## you should check a valid user is checked in. You are encouraged to wrap this behavour in a function.
            response = []
            iuser = user_magic[0]
            imagic = user_magic[1]
            if handle_validate(iuser, imagic) != True:
                response.append(build_response_redirect("/index.html"))
            else:
                # row = access_database_with_results('traffic.db', "SELECT time from traffic where mode =1")
                today_stamp = access_database_with_results('traffic.db', "SELECT min(time) FROM traffic where mode = 1")[0][0]
                data = access_database_with_results('traffic.db', f"SELECT time, location, type, COUNT(occupancy=1 OR null), COUNT(occupancy=2 OR null), COUNT(occupancy=3 OR null), COUNT(occupancy=4 OR null) from traffic where mode = 1 and time > {today_stamp} GROUP BY location, type")
                if data != []:
                    for i in range(len(data)):
                        date_original = tuple(time.localtime(data[i][0]))
                        if data[i][0] > today_stamp:
                            recent_date = data[i][0]
                            date = tuple(time.localtime(recent_date))
                            if (date[0] == date_original[0]) and (date[1] == date_original[1]) and (date[2] == date_original[2]):
                                text = "Location,Type,Occupancy1,Occupancy2,Occupancy3,Occupancy4\n"
                                for i in range(len(data)):
                                    location = data[i][1]
                                    if data[i][2] == 0:
                                        type = "car"
                                    if data[i][2] == 1:
                                        type = "van"
                                    if data[i][2] == 2:
                                        type = "truck"
                                    if data[i][2] == 3:
                                        type = "taxi"
                                    if data[i][2] == 4:
                                        type = "other"
                                    if data[i][2] == 5:
                                        type = "motorbike"
                                    if data[i][2] == 6:
                                        type = "bicycle"
                                    if data[i][2] == 7:
                                        type = "bus"
                                    occupancy1 = data[i][3]
                                    occupancy2 = data[i][4]
                                    occupancy3 = data[i][5]
                                    occupancy4 = data[i][6]
                                    
                                    text += f"{location}, {type}, {occupancy1}, {occupancy2}, {occupancy3}, {occupancy4}\n"
                                
            encoded = bytes(text, 'utf-8')
            self.send_response(200)
            self.send_header('Content-type', 'text/csv')
            self.send_header("Content-Disposition", 'attachment; filename="{}"'.format('traffic.csv'))
            self.send_header("Content-Length", len(encoded))
            self.end_headers()
            self.wfile.write(encoded)

        else:
            # A file that does n't fit one of the patterns above was requested.
            self.send_response(404)
            self.end_headers()
        return

def run():
    """This is the entry point function to this code."""
    print('starting server...')
    ## You can add any extra start up code here
    # Server settings
    # Choose port 8081 over port 80, which is normally used for a http server
    if(len(sys.argv)<2): # Check we were given both the script name and a port number
        print("Port argument not provided.")
        return
    server_address = ('127.0.0.1', int(sys.argv[1]))
    httpd = HTTPServer(server_address, myHTTPServer_RequestHandler)
    print('running server on port =',sys.argv[1],'...')
    httpd.serve_forever() # This function will not return till the server is aborted.

run()
