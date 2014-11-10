# coding=utf-8
from datetime import datetime, timedelta
import time
import webapp2
import jinja2
import os
import logging
import string
import json
import urllib2
import random
import hmac
import urlparse
import cgi
import hashlib
import re
from math import sqrt
from unidecode import unidecode

import facebook
from google.appengine.api.images import get_serving_url, resize
from google.appengine.ext import blobstore
from google.appengine.api import urlfetch
from google.appengine.api import mail
from google.appengine.api import memcache
from google.appengine.ext import ndb
from webapp2_extras import sessions



#########DATABASE CLASSES#####

class User(ndb.Model):
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)
    name = ndb.StringProperty(required=True)
    first_name = ndb.StringProperty(required=True)
    second_name = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=True)
    password = ndb.StringProperty()
    fb_profile_url = ndb.StringProperty()
    fb_uid = ndb.StringProperty()
    fb_access_token = ndb.StringProperty()
    google_profile_url = ndb.StringProperty()
    google_user_id = ndb.StringProperty()
    google_profile_pic_url = ndb.StringProperty()
    google_access_token = ndb.StringProperty()
    active_pic = ndb.StringProperty()
    gender = ndb.StringProperty()
    user_active_pic = ndb.StringProperty()
    confirm_email_hash = ndb.StringProperty()
    fb_profile_pic = ndb.BlobProperty()
    show_member_on_start = ndb.BooleanProperty(default = True)

class School(ndb.Model):
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)
    name = ndb.StringProperty(required=True)
    email = ndb.StringProperty()
    password = ndb.StringProperty()
    gmaps_id = ndb.StringProperty(required=True)
    gmaps_ref = ndb.StringProperty(required=True)
    coordinates = ndb.GeoPtProperty(required=True)
    num_groups = ndb.IntegerProperty()
    num_students = ndb.IntegerProperty()
    is_authorized = ndb.BooleanProperty()
    kind = ndb.StringProperty(repeated=True) #university/school?
    num_authorized = ndb.IntegerProperty(default = 0)
    places_url = ndb.StringProperty()

    
class Group(ndb.Model):
    admins = ndb.KeyProperty(repeated=True)
    members = ndb.KeyProperty(repeated=True)
    awaiting_members = ndb.KeyProperty(repeated=True)
    creator = ndb.KeyProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)
    name = ndb.StringProperty(required=True)
    description = ndb.TextProperty()
    is_public = ndb.BooleanProperty()
    is_approvable = ndb.BooleanProperty()
    is_authorized = ndb.BooleanProperty(default=False)
    admin_topics = ndb.KeyProperty(repeated=True)
    user_topics = ndb.KeyProperty(repeated=True)
    in_school = ndb.BooleanProperty(default=False)
    
class Topic(ndb.Model):
    created = ndb.DateTimeProperty(auto_now_add=True)
    creator = ndb.KeyProperty(required=True)
    admins = ndb.KeyProperty(repeated=True)
    admin_references = ndb.KeyProperty(repeated=True)
    user_references = ndb.KeyProperty(repeated=True)
    updated = ndb.DateTimeProperty(auto_now=True)
    name = ndb.StringProperty(required=True)
    description = ndb.TextProperty()
    ranking = ndb.IntegerProperty()
    in_groups = ndb.IntegerProperty(default = 0)
    in_authorized_groups = ndb.IntegerProperty(default = 0)
    keywords = ndb.StringProperty(repeated = True)
    is_public = ndb.BooleanProperty(default = False)
    
class Event(ndb.Model):
    name = ndb.StringProperty(required=True)
    updated = ndb.DateTimeProperty(auto_now=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    creator = ndb.KeyProperty(required=True)
    starting_day = ndb.DateTimeProperty(required = True)
    starting_day_utc = ndb.StringProperty(required = True)
    repetition = ndb.StringProperty()
    exceptions = ndb.StringProperty()
    description = ndb.StringProperty()
    by_member = ndb.BooleanProperty()
    
class Task(ndb.Model):
    name = ndb.StringProperty(required=True)
    updated = ndb.DateTimeProperty(auto_now=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    creator = ndb.KeyProperty(required=True)
    due = ndb.DateTimeProperty(required = True)
    due_utc = ndb.StringProperty(required = True)
    description = ndb.StringProperty()
    by_member = ndb.BooleanProperty()
    
class Reference(ndb.Model):
    name = ndb.StringProperty(required=True)
    updated = ndb.DateTimeProperty(auto_now=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    creator = ndb.KeyProperty(required=True)
    description = ndb.StringProperty()
    ref_type = ndb.StringProperty(required=True)
    url = ndb.StringProperty(required=True)
    up_votes = ndb.IntegerProperty(default = 0)
    down_votes = ndb.IntegerProperty(default = 0)
    up_voted_by = ndb.KeyProperty(repeated = True)
    down_voted_by = ndb.KeyProperty(repeated = True)
    by_member = ndb.BooleanProperty(default = False)
    
class Comment(ndb.Model):
    updated = ndb.DateTimeProperty(auto_now=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    creator = ndb.KeyProperty(required=True)
    content = ndb.TextProperty(required=True)
#####END DATABASE CLASSES####

config = {}
config['webapp2_extras.sessions'] = dict(secret_key='much secret', session_max_age=2592000)
#2 592 000 = 30 days in sec

FACEBOOK_APP_ID = "HIDDEN"
FACEBOOK_APP_SECRET = "HIDDEN"
GOOGLE_CLIENT_ID = "HIDDEN"
CSRF_SECRET = "HIDDEN"
COOKIE_SECRET = "HIDDEN"

class BaseHandler(webapp2.RequestHandler):
    #init jinja
    jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))
    
    def dispatch(self):
        """
        This snippet of code is taken from the webapp2 framework documentation.
        See more at
        http://webapp-improved.appspot.com/api/webapp2_extras/sessions.html

        """
        self.session_store = sessions.get_store(request=self.request)
        try:
            webapp2.RequestHandler.dispatch(self)
        finally:
            self.session_store.save_sessions(self.response)
            
            
    @webapp2.cached_property
    def session(self):
        """
        This snippet of code is taken from the webapp2 framework documentation.
        See more at
        http://webapp-improved.appspot.com/api/webapp2_extras/sessions.html

        """
        return self.session_store.get_session()
    
    def generate_csrf_token(self, name, email):
        salt = ''.join(random.choice(string.letters + string.digits) for x in range(10))
        name = unidecode(name)
        email = unidecode(email)
        return hmac.new(CSRF_SECRET, name + email + salt).hexdigest() + salt

    def check_csrf_token(self, token, name, email):
        salt = token[-10:]
        name = unidecode(name)
        email = unidecode(email)
        if hmac.new(CSRF_SECRET, name + email + salt).hexdigest() + salt == token:
            return True
        else: return False
    
    def hash_for_cookie(self, s):
        return hmac.new(COOKIE_SECRET, s).hexdigest()
    
    def check_cookie(self, s):
        if s:
            unencrypted_val, encrypted_val = s.rpartition("|")[0], s.rpartition("|")[2]
            if hmac.new(COOKIE_SECRET, unencrypted_val).hexdigest() == encrypted_val:
                return True
        return False
        
    def set_cookie(self, cookie_name, string, path="/"):
        if string:
            expires = time.time() + 30 * 24 * 3600
        else:
            expires = time.time()
        expires_formatted = time.strftime("%a, %d-%b-%Y %T GMT", time.gmtime(expires))
        hash_value = self.hash_for_cookie(string)
        finished_cookie = "%s|%s" % (string, hash_value)
        self.response.headers.add_header('Set-Cookie', str('%s=%s; expires=%s; Path=%s' % (cookie_name, finished_cookie, expires_formatted, path)))
    
    def set_session(self, user, session_name="user"):
        """ Given a user object this function creates a session cookie. 
            Only works if user has already been put into db. Else 
            user.key.integer_id() will fail."""
        self.set_cookie("login", user.key.urlsafe())
        
        self.session[session_name] = dict(
            uid = user.key.integer_id(),
            name=user.name,
            email = user.email,
            fb_profile_url=user.fb_profile_url,
            fb_uid=user.fb_uid,
            google_profile_url= user.google_profile_url,
            google_user_id = user.google_user_id,
            key = user.key.urlsafe(),
            profile_pic = self.get_active_profile_image(user))
    
    def logout(self):
        self.set_cookie("login", "")
        self.session['user'] = None
    
    def render(self, template_name, *args, **kwargs):
        """Loads template and renders it."""
        
        html_to_cache_list = [""]
        
        if template_name in html_to_cache_list:
            p = memcache.get(template_name)
            if not p: 
                p = self.jinja_environment.get_template(template_name).render(**kwargs)
                memcache.set(template_name, p)
        else:
            p = self.jinja_environment.get_template(template_name).render(**kwargs)
        
        self.response.out.write(p)
        
    def print_json(self, dict):
        self.response.headers['Content-Type'] = "application/json"
        self.response.out.write(json.dumps(dict))
        
    def is_logged_in(self):
        """Returns True or False wether User is logged in or not."""
        valid_login_cookie = self.check_cookie(self.request.cookies.get("login"))
        session = self.session.get("user")
        if valid_login_cookie and session:
            return True
        elif valid_login_cookie and not session: 
            urlsafe_key = self.request.cookies.get("login").rpartition("|")[0]
            user = ndb.Key(urlsafe=urlsafe_key).get()
            if user:
                self.set_session(user)
                return True
        return False

    def get_active_profile_image(self, user, big = False):
        parameters = ""
        if user.google_profile_pic_url and user.active_pic != "facebook" and user.active_pic != "no":
            if big: return user.google_profile_pic_url[:-5]
            return user.google_profile_pic_url
        
        elif user.fb_uid and user.active_pic !="google" and user.active_pic != "no":
            if big:  parameters ="&width=256&height=256"
            return ("/users/%s/serveImage" % user.key.urlsafe())
        else:
            if user.gender == "female":
                if big: return "/static/images/avatar_250px_f.png"
                return "/static/images/avatar_50px_f.png"
            else:
                if big: return "/static/images/avatar_250px_m.png"
                return "/static/images/avatar_50px_m.png"
    
    def make_salt(self, n=5):
            return ''.join(random.choice(string.letters + string.digits) for x in xrange(n))
    
    def is_valid_password(self, s):
        if s:
            PASSWORD_RE = re.compile(r"^.{5,20}$")
            return PASSWORD_RE.match(s)
        else: return False
    
    def is_valid_email(self, email):
        if email:
            EMAIL_RE =  re.compile(r"^[\S]+@[\S]+\.[\S]+$")
            return EMAIL_RE.match(email)
        else: return False
        
    def get_number_of_words(self, to_do_string, n=10, add_points=False):
        
        to_do_string = to_do_string.replace("\n", " ")
        to_do_string = to_do_string.replace("<br />", " ")
        
        to_do_string = to_do_string.replace("<br>", " ")
        return_string = ""
        splitted = to_do_string.split(" ")
        words_so_far = 1
        
        if not to_do_string:
            return ""
        
        for word in splitted:
            if words_so_far > n:
                break
            elif word:
                return_string += (word + " ")
            words_so_far += 1
        
        if add_points and len(splitted) > n:
            return_string += " ... "
        
        return return_string
    
    def get_tasks_or_events(self, group_key, get_events=False, return_json=False, n=None):
        oldest_shown = self.request.get('oldest')
        return_dict = {"by_admin": [],
                       "by_member": []}
        
        if oldest_shown:
            oldest_shown_entity = ndb.Key(urlsafe=oldest_shown).get()
            if oldest_shown_entity:
                qry = ndb.gql("SELECT * from Task WHERE ANCESTOR IS :1 AND due > :2 ORDER BY due ASC",
                          ndb.Key(urlsafe=group_key), oldest_shown_entity.due)
                if get_events:
                    qry = ndb.gql("SELECT * from Event WHERE ANCESTOR IS :1 AND starting_day > :2 ORDER BY starting_day ASC",
                           ndb.Key(urlsafe=group_key), oldest_shown_entity.starting_day)
            else:
                logging.error("Last entity not found")
                return
        else:
            qry = ndb.gql("SELECT * from Task WHERE ANCESTOR IS :1 AND due > :2 ORDER BY due ASC",
                          ndb.Key(urlsafe=group_key), datetime.utcnow())
            if get_events:
                qry = ndb.gql("SELECT * from Event WHERE ANCESTOR IS :1 AND starting_day > :2 ORDER BY starting_day ASC",
                          ndb.Key(urlsafe=group_key), datetime.utcnow())

        for entity in qry.fetch(n):
            if entity.by_member:
                return_dict["by_member"].append(entity)
            else:
                return_dict["by_admin"].append(entity)
        
        if return_json:
            self.print_json(return_dict)
        else:
            return (return_dict["by_admin"], return_dict["by_member"])
                    
class AddToGroupPage(BaseHandler):

    def get(self, group_key):
        if not self.is_logged_in():
            self.redirect("/")
            return
        user_from_cookie = self.session.get("user")
        user_key = ndb.Key(urlsafe=user_from_cookie["key"])
        name = user_from_cookie["name"]
        email = user_from_cookie["email"]
        csrf_token = self.generate_csrf_token(name, email)
        
        
        qry = Topic.query(Topic.admins == user_key)
        qry.filter(ndb.OR(Topic.creator == user_key))
        user_topics = qry.fetch(None)
        
        self.render("add_to_group_page.html", 
                    csrf_token=csrf_token,
                    user_topics = user_topics)
        return
    
    def post(self, group_key):
        if self.is_logged_in():
            to_add_topics = self.request.get_all("topic")
            csrf_token = self.request.get('dontCSRFme')
            user_from_cookie = self.session.get('user')
            user_name = user_from_cookie["name"]
            user_email = user_from_cookie["email"]
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            topics = []
            
            
            if to_add_topics and self.check_csrf_token(csrf_token, user_name, user_email):
                group = ndb.Key(urlsafe=group_key).get()
                if group and user_key in group.admins:
                    for topic in to_add_topics:
                        if ndb.Key(urlsafe=topic) not in group.admin_topics:
                            group.admin_topics.append(ndb.Key(urlsafe=topic))
                    group.put()
                    
                elif group and user_key in group.members:
                    for topic in to_add_topics:
                        if ndb.Key(urlsafe=topic) not in group.user_topics:
                            group.user_topics.append(ndb.Key(urlsafe=topic))
                    group.put()
                    
        self.redirect('/groups/%s' % group_key)
        return
    
    
class SchoolSearch(BaseHandler):
    
    def get_school_data(self, keyword):
        repl_dict = {"keyword": keyword.replace(" ","%20")} #no spaces in urls
        
        gmaps_url = ("https://maps.googleapis.com/maps/api/place/textsearch/" 
            "json?key=THEKEY"
            "&sensor=false&"
            "query=%(keyword)s&types=school|university")
        
        return_dict = {"status": "ok", "schools" : []}
        
        p = urllib2.urlopen(gmaps_url % repl_dict)
        parsed_response = json.loads(p.read())
        
        if parsed_response["status"] == "OK":
            for returned_school in parsed_response["results"][0]:
                school = parsed_response["results"][0]
                return_dict["schools"].append({
                    "name" : school["name"],
                    "gmaps_id" : school["id"],
                    "gmaps_reference": school["reference"]
                })
                
            return_dict["status"] = "ok"
                
        return return_dict
    
    def remove_duplicates(self, dictionary):
        if dictionary and "schools" in dictionary and dictionary["schools"]:
            all_schools = dictionary["schools"]
            without_duplicates = []
            got_already = []
            
            for school in all_schools:
                if school["gmaps_id"] in got_already:
                    pass
                else:
                    without_duplicates.append(school)
                    got_already.append(school["gmaps_id"])
            dictionary["schools"] = without_duplicates
            return dictionary
        else:
            return dictionary
    
    def get(self):
        school_name = self.request.get("school_name")
        if school_name:
            self.print_json(self.remove_duplicates(self.get_school_data(school_name)))
            return
                
                
class CreateGroup(BaseHandler):
    
    def get(self):
        if self.is_logged_in():
            user_from_cookie = self.session.get("user")
            name = user_from_cookie["name"]
            email = user_from_cookie["email"]
            csrf_token = self.generate_csrf_token(name, email)
            self.render("create_group_page.html", csrf_token = csrf_token)
            return
        self.redirect('/')
    
    
    
    
        
    
    def post(self):
        """If school was entered, looks it up on GMaps. Checks if already in
        our DB, if not puts it there. It it is in our DB it increments the
        num_groups value. Race Conditions may occur.
        Next it will create the group and put it in the DB. If it has been 
        assigned to a school it will be stored as a child of it."""
        
        if not self.is_logged_in():
            self.redirect("/")
            return
        
        school_gmaps_ref = self.request.get('school')
        csrf_token = self.request.get("dontCSRFme")
        group_name = self.request.get("group_name")
        description = self.request.get("group_description")
        is_public = self.request.get("public")
        is_approvable = self.request.get("approvable")
        csrf_token = self.request.get("dontCSRFme")
        user_from_cookie = self.session.get("user")
        name = user_from_cookie["name"]
        email = user_from_cookie["email"]        
        school = ""
        
        if not self.check_csrf_token(csrf_token, name, email):
            self.print_json({"status" : "error", "msg" : "Post not allowed"})
            return
                
        
        if school_gmaps_ref:
            places_api_url = "https://maps.googleapis.com/maps/api/place/details/json?key=THEKEY&sensor=false&reference=%s" % school_gmaps_ref
            p = urllib2.urlopen(places_api_url)
            parsed_response = json.loads(p.read())
            
            school = ndb.gql("SELECT * FROM School WHERE gmaps_id = :1",
                                     parsed_response["result"]["id"]).get()
            if school:
                school.num_groups += 1
            else:
                school = School(name = parsed_response["result"]["name"],
                                gmaps_id = parsed_response["result"]["id"],
                                coordinates = ndb.GeoPt(parsed_response["result"]["geometry"]["location"]["lat"],
                                                        parsed_response["result"]["geometry"]["location"]["lng"]),
                                num_groups = 1,
                                kind = parsed_response["result"]["types"],
                                gmaps_ref = parsed_response["result"]["reference"])
                if "url" in parsed_response["result"]: school.places_url = parsed_response["result"]["url"]
                
            school.put()
        
        # If a school was entered by the user, it has been added to the db.
        # We can now proceed. We need to keep in mind that some entries will
        # have the school as parent, some not.
        
        if group_name:
            if school: 
                group = Group(parent=ndb.Key(urlsafe=school.key.urlsafe()),
                              name = cgi.escape(group_name), 
                              description = cgi.escape(description),
                              creator = ndb.Key(urlsafe=user_from_cookie["key"]),
                              admins = [ndb.Key(urlsafe=user_from_cookie["key"])],
                              members = [],
                              in_school = True
                              )
            else:
                group = Group(name = cgi.escape(group_name), 
                              description = cgi.escape(description),
                              creator = ndb.Key(urlsafe=user_from_cookie["key"]),
                              admins = [ndb.Key(urlsafe=user_from_cookie["key"])],
                              members = [])
            
            if is_approvable: group.is_approvable = True
            if is_public: group.is_public = True
            group.put()
            if school:
                self.print_json({"status": "ok" , "key" : group.key.urlsafe(), 
                                 "school_added": True})
            else:
                self.print_json({"status": "ok", "key" : group.key.urlsafe(), 
                                 "school_added": False})
        else:
            self.print_json({"status":"error", "msg":"Invalid post or no name or description entered."})
                

    
class HomePage(BaseHandler):
    def get(self):
        if self.is_logged_in():
            user_from_cookie = self.session.get('user')
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            user = user_key.get()
            admin_groups = Group.query(Group.admins.IN([user_key]))
            admin_groups.filter(ndb.OR(Group.creator == user_key))
            admin_groups = admin_groups.fetch(None)
            member_groups = Group.query(Group.members == user_key).fetch(None)
            
            
            admin_topics = Topic.query(Topic.creator == user_key, ndb.OR(Topic.admins == user_key)).fetch(5)
            
            
            admin_tasks = []
            member_tasks = []
            admin_events = []
            member_events = []

            
            for group in (admin_groups + member_groups):
                group_tasks = self.get_tasks_or_events(group.key.urlsafe(), n=5)
                group_events = self.get_tasks_or_events(group.key.urlsafe(), n=5, get_events = True)
                
                for task in group_tasks[0]:
                    admin_tasks.append(((self.get_number_of_words(group.name, n=4, add_points = True), group.key.urlsafe()), task))
                    #get_number_of_words(self, string, n=10, add_points=False)
                for event in group_events[0]:
                    admin_events.append(((self.get_number_of_words(group.name, n=4, add_points = True), group.key.urlsafe()), event))
                
                if user.show_member_on_start:
                    
                    for task in group_tasks[1]:
                        member_tasks.append(((self.get_number_of_words(group.name, n=4, add_points=True), group.key.urlsafe()), task))
                    
                    for event in group_events[1]:
                        member_events.append(((self.get_number_of_words(group.name, n=4, add_points=True), group.key.urlsafe()), event))
                
                
            admin_tasks.sort(key = lambda task: task[1].due)
            member_tasks.sort(key = lambda task: task[1].due)
            admin_events.sort(key = lambda event: event[1].starting_day)
            member_events.sort(key = lambda event: event[1].starting_day)
            
            self.render("home_page.html",
                        admin_tasks = admin_tasks[:5],
                        member_tasks = member_tasks[:5],
                        admin_events = admin_events[:5],
                        member_events = member_events[:5],
                        admin_topics = admin_topics[:5],
                        admin_groups = admin_groups[:5],
                        member_groups = member_groups[:5],
                        user = user)
            
            
        else:
            self.render('index.html')

class ViewAllHandler(BaseHandler):
    
    def view_all(self, admin_or_member, kind):
        
        if self.is_logged_in():
            user_from_cookie = self.session.get('user')
            user_key = ndb.Key(urlsafe=user_from_cookie['key'])
            
            admin_groups = Group.query(Group.admins.IN([user_key]))
            admin_groups.filter(ndb.OR(Group.creator == user_key))
            admin_groups = admin_groups.fetch(None)
            member_groups = Group.query(Group.members == user_key).fetch(None)
                        
            finished_list = []
            #def get_tasks_or_events(self, group_key, get_events=False, return_json=False):

            for group in (member_groups + admin_groups):
                
                if kind == "events":
                    all_entities = self.get_tasks_or_events(group.key.urlsafe(), get_events=True)
                else:
                    all_entities = self.get_tasks_or_events(group.key.urlsafe())
                
                if admin_or_member == "Member": i = 1
                else: i = 0
                
                for entity in all_entities[i]:
                    if entity.description:
                        entity.description = self.get_number_of_words(entity.description, n=5, add_points=True)
                    finished_list.append(((group.name, group.key.urlsafe()), entity))
            
            if finished_list:
                self.render("view_all.html",
                            entities = sorted(finished_list, key=lambda e: e[1].due),
                            entity_type = kind,
                            added_by = admin_or_member + 's')
                return
        
        self.redirect('/')
        return            
            
            
class ViewAllAdminTasks(ViewAllHandler):
    def get(self):
        self.view_all("Admin", "tasks")
        return
    
    
class ViewAllMemberTasks(ViewAllHandler):
    def get(self):
        self.view_all("Member", "tasks")
        return
    
class ViewAllAdminEvents(ViewAllHandler):
    def get(self):
        self.view_all("Admin", "events")
        return
    
    
class ViewAllMemberEvents(ViewAllHandler):
    def get(self):
        self.view_all("Member", "events")
        return
    
            
class FBChannelFile(BaseHandler):
    def get(self):
        self.response.out.write('<script src="//connect.facebook.net/en_US/all.js"></script>')
        
class FacebookLogin(BaseHandler):
    
    def sign_in_facebook_user(self, cookie):
        """Signs in user and adds him to database if he's not already in it."""

        graph = facebook.GraphAPI(cookie["access_token"])
        profile = graph.get_object("me")
        
        user = ndb.gql("SELECT * from User WHERE email = :1", profile["email"]).get()

        if not user:
            #User is not in our db.
            user = User(
                fb_uid = profile["id"],
                name = profile["name"],
                email = profile["email"],
                fb_profile_url = profile["link"],
                gender = profile["gender"],
                fb_profile_pic = (urlfetch.Fetch("https://graph.facebook.com/%s/picture?access_token=%s&width=250&height=250" % (profile["id"], cookie["access_token"])).content),
                first_name = profile["first_name"],
                second_name = profile["last_name"])

        elif user and not user.fb_uid and not user.fb_profile_url:
            #User is in db and has never logged in using Facebook before. 
            user.fb_uid = profile["id"]
            user.fb_profile_url = profile["link"]
            user.fb_profile_pic = (urlfetch.Fetch("https://graph.facebook.com/%s/picture?access_token=%s&width=250&height=250" % (profile["id"], cookie["access_token"])).content)

        user.fb_access_token = cookie["access_token"]
        user.put()    
        #Now we can add the session cookie for the user.
        self.set_session(user)
        
        
    def get(self):
        
        # There are three possible cases here:
            #Case 1:    The user already has a session cookie and thus is logged in.
            #           We will redirect him to home.
            #Case 2:    The user has succesfully logged in with Facebook using the JavaScript SDK
            #           Depending on whether he already is in our database we will add him or not
            #           and add a session cookie for him.
            #Case 3:    The user has no session cookie and has not logged in using the JavaScript SDK.
            #           We will just redirect him to home.
        
        cookie = facebook.get_user_from_cookie(self.request.cookies,
                                                   FACEBOOK_APP_ID,
                                                   FACEBOOK_APP_SECRET)
                                                
        #Case 1
        if self.session.get('user'):
            self.redirect("/")
        
        #Case 2
        elif cookie:
            self.sign_in_facebook_user(cookie)
            self.redirect("/")
        
        #Case 3
        else:
            self.redirect("/")
            
class GooglePlusSignIn(BaseHandler):

    def get_user_id_and_email(self, token):
        ###First we need to validate the token. For more information visit https://developers.google.com/accounts/docs/OAuth2UserAgent#validatetoken
        try:
            p = urllib2.urlopen("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s" % token)
        except urllib2.HTTPError, err:
            return (None, None)
        
        parsed_response = json.loads(p.read())
        if not "error" in parsed_response and parsed_response['audience'] == GOOGLE_CLIENT_ID:
            return parsed_response["user_id"], parsed_response["email"]
        else: 
            return (None,None)
        
    def sign_in_google_plus_user(self, user_id, access_token, email):
        p = urllib2.urlopen('https://www.googleapis.com/plus/v1/people/%(user_id)s?access_token=%(access_token)s' % {"user_id": user_id, "access_token": access_token})
        parsed_response = json.loads(p.read())
        user = ndb.gql("SELECT * from User WHERE email = :1", email).get()
        if user and not user.google_profile_url and not user.google_user_id:
            user.google_profile_url, user.google_user_id = parsed_response['url'], user_id
            user.google_profile_pic_url = parsed_response["image"]["url"]
            if "gender" in parsed_response:
                user.gender = parsed_response["gender"]
            else:
                user.gender = "other"
            user.google_access_token = access_token
            user.put()
            self.set_session(user)
            return
        elif not user:
            user = User(
                name = parsed_response['displayName'],
                email = email,
                google_profile_url = parsed_response['url'],
                google_user_id = user_id,
                google_profile_pic_url = parsed_response["image"]["url"],
                google_access_token = access_token,
                first_name = parsed_response["name"]["givenName"],
                second_name = parsed_response["name"]["familyName"])
            if "gender" in parsed_response:
                user.gender = parsed_response["gender"]
            user.put()
            self.set_session(user)
            return
        elif user:
            user.google_profile_pic_url = parsed_response["image"]["url"]
            user.google_access_token = access_token
            user.put()
        
        self.set_session(user)
            
        
        

        
    
    def get(self):
        access_token = self.request.cookies.get('google_plus_sign_in')
        self.response.headers.add_header('Set-Cookie', str('google_plus_sign_in=; Path=/'))
        user_id, email = self.get_user_id_and_email(access_token)
        
        if user_id:
            self.sign_in_google_plus_user(user_id, access_token, email)
            self.redirect('/')
        else:
            self.redirect('/')
        

class GetGroups(BaseHandler):
    def get(self):
        return_dict = {"status": "ok", "groups": []}
        if self.is_logged_in():
            user_from_cookie = self.session.get("user")
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            groups = ndb.gql("SELECT * FROM Group WHERE admins = :1", user_key).fetch(None)
            for group in groups:
                return_dict["groups"].append({"name": group.name,
                                              "key": group.key.urlsafe()})
        else:
            return_dict["status"] = "error"
            
        self.print_json(return_dict)
        return
            
class CreateTopic(BaseHandler):
    def post(self, group_key):
        user_from_cookie = self.session.get("user")
        name = user_from_cookie["name"]
        email = user_from_cookie["email"]  
        csrf_token = self.request.get("dontCSRFme")
        
        if self.check_csrf_token(csrf_token, name, email) and self.is_logged_in():
            
            topic_name = cgi.escape(self.request.get("topic_name"))
            topic_description = cgi.escape(self.request.get("topic_description"))
            is_public = self.request.get("public")
            keywords = cgi.escape(self.request.get('keywords'))
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            
            #First we'll check if the group exists and adapt its counter
            # whether it is an authorized one or not.
            if topic_name:
                group = ndb.Key(urlsafe=group_key).get()
                
                if not group: 
                    self.print_json({"status": "error", "msg": "group not found"})
                    return
                
                if user_key not in group.admins and user_key not in group.members:
                    self.print_json({"status": "error", "msg": "user not authorized"})
                    return
                
                topic = Topic(creator = ndb.Key(urlsafe=user_from_cookie["key"]),
                              admins = [ndb.Key(urlsafe=user_from_cookie["key"])],
                              name = topic_name,
                              description = cgi.escape(topic_description),
                              ranking = 0,
                              )
                if is_public:
                    topic.is_public = True
                
                if group.is_authorized:
                    topic.in_authorized_groups += 1
                else:
                    topic.in_groups += 1
                    
                if is_public:
                    entered_keywords = list(set(keywords.split(' ') + topic_name.split(" ")))
                    keywords_for_db = []
                    for w in entered_keywords:
                        if len(w) > 1 and w != " ":
                            keywords_for_db.append(w.lower())
                    topic.keywords = keywords_for_db    
                
                topic.put()
                
                if user_key in group.admins:
                    group.admin_topics.append(topic.key)
                elif user_key in group.members:
                    group.user_topics.append(topic.key)
                    
                group.put()
                
                self.print_json({"status": "ok", "key": topic.key.urlsafe()})
                return

class ReferenceRanking():
    def _confidence(self, ups, downs):
        n = ups + downs

        if n == 0:
            return 0

        z = 1.0 #1.0 = 85%, 1.6 = 95%
        phat = float(ups) / n
        return sqrt(phat+z*z/(2*n)-z*((phat*(1-phat)+z*z/(4*n))/n))/(1+z*z/n)

    def confidence(self, ups, downs):
        if ups + downs == 0:
            return 0
        else:
            return self._confidence(ups, downs)
    
    def return_score(self, reference_object):
        return self.confidence(reference_object.up_votes, reference_object.down_votes)
            
class TopicPage(BaseHandler, ReferenceRanking):
    
    def get(self, topic_key):
        
        user_key = ""
        user_profile_pic = ""
        csrf_token = ""
        user_profile_pic = ""
        is_logged_in = self.is_logged_in()
        
        if is_logged_in:
            is_logged_in = True
            user_from_cookie = self.session.get('user')
            user_name = user_from_cookie["name"]
            user_email = user_from_cookie["email"]
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            csrf_token = self.generate_csrf_token(user_name, user_email)
            user_profile_pic = user_from_cookie["profile_pic"]
        
        topic = ndb.Key(urlsafe=topic_key).get()
        if topic:
            admin_references = Reference.query(Reference.by_member == False, ancestor=ndb.Key(urlsafe=topic_key)).fetch(5)
            member_references = Reference.query(Reference.by_member == True, ancestor=ndb.Key(urlsafe=topic_key)).fetch(5)
            
            admin_references.sort(key=self.return_score, reverse=True)
            member_references.sort( key=self.return_score, reverse=True)
            
        
            self.render("topic_page.html",
                        topic = topic,
                        admin_references = admin_references,
                        member_references = member_references,
                        csrf_token = csrf_token,
                        user_key = user_key,
                        user_profile_pic = user_profile_pic,
                        is_logged_in = is_logged_in,
                        url = self.request.url,
                        meta_topic_description = self.get_number_of_words(topic.description, n=25, add_points = True))
            return
        
        else:
            self.redirect('/')
            return
        
class GroupAddPage(BaseHandler):
    def get(self, group_key):
        
        if ndb.Key(urlsafe=group_key).get():
            if self.is_logged_in():
                user_from_cookie = self.session.get("user")
                name = user_from_cookie["name"]
                email = user_from_cookie["email"]
                csrf_token = self.generate_csrf_token(name, email)
                self.render("add_date_task.html", csrf_token = csrf_token)
                return
        self.redirect('/groups/%s' % group_key)
        return
                   
                
class AddEvent(BaseHandler):
        
    def post(self, group_key):
        
        user_from_cookie = self.session.get("user")
        name = user_from_cookie["name"]
        email = user_from_cookie["email"]  
        csrf_token = self.request.get("dontCSRFme")
        if self.check_csrf_token(csrf_token, name, email) and self.is_logged_in():
            user = ndb.Key(urlsafe=user_from_cookie["key"])
            group = ndb.Key(urlsafe=group_key).get()
            if group and (user in group.members or user in group.admins):
                name = cgi.escape(self.request.get("event_name"))
                description = cgi.escape(self.request.get("event_description"))
                utc_date_string = self.request.get("single_calendar_date")
                
                if name and utc_date_string:
                    #First we create a datetime object  
                    frmt = "%a, %d %b %Y %H:%M:%S %Z"
                    try:
                        first_event = datetime.strptime(utc_date_string, frmt)
                    except:
                        logging.error("exception: invalid utc string")
                        self.print_json({"status": "error", "msg": "invalid utc string"})
                        return
                    #now we have a datetime object for the first occurence of
                    #the event. We proceed by putting it in our Event db. 
                    
    
                    
                    event = Event(parent = ndb.Key(urlsafe=group_key),
                                  name = name,
                                  creator = ndb.Key(urlsafe=user_from_cookie["key"]),
                                  starting_day = first_event,
                                  description = description,
                                  starting_day_utc = utc_date_string)
                    if user in group.members:
                        event.by_member = True
                    event.put()
                    self.print_json({"status": "ok", "key": event.key.urlsafe()})
                    return
            else:
                    self.print_json({"status":"error", "msg": "Group not found"})
                    return
                            

class AddTask(BaseHandler):
    def post(self, group_key):
        
        user_from_cookie = self.session.get("user")
        name = user_from_cookie["name"]
        email = user_from_cookie["email"]  
        csrf_token = self.request.get("dontCSRFme")
        task_name = cgi.escape(self.request.get("task_name"))
        task_description = cgi.escape(self.request.get("task_description"))
        utc_date_string = self.request.get("single_calendar_date")
        group = ndb.Key(urlsafe=group_key).get()
        
        if task_name and utc_date_string and self.check_csrf_token(csrf_token, name, email) and self.is_logged_in() and group:
            user = ndb.Key(urlsafe=user_from_cookie["key"])
            if user in group.members or user in group.admins:
                #First we create a datetime object  
                frmt = "%a, %d %b %Y %H:%M:%S %Z"
                try:
                    task_date = datetime.strptime(utc_date_string, frmt)
                except:
                    logging.error("exception: invalid utc string")
                    self.print_json({"status": "error", "msg": "invalid utc string"})
                    return
                
                task = Task(parent = ndb.Key(urlsafe=group_key),
                            name = task_name,
                            creator = ndb.Key(urlsafe=user_from_cookie["key"]),
                            description = task_description,
                            due = task_date,
                            due_utc = utc_date_string)
                if user in group.members:
                    task.by_member = True
                
                task.put()
                self.print_json({"status": "ok", "key": task.key.urlsafe()})
                return
            
        else:
            self.print_json({"status": "error", "msg": "Invalid form data or group not found."})
            return

class ReferenceAddPage(BaseHandler):
    def get(self,topic_key):
        if self.is_logged_in():
            user_from_cookie = self.session.get("user")
            name = user_from_cookie["name"]
            email = user_from_cookie["email"]
            csrf_token = self.generate_csrf_token(name, email)
            if ndb.Key(urlsafe=topic_key).get():
                self.render("add_reference.html", csrf_token = csrf_token)
                return
            else:
                self.error(404)
                return

class AddReference(BaseHandler):
    def post(self, topic_key):
        if self.is_logged_in():
            user_from_cookie = self.session.get("user")
            user_name = user_from_cookie["name"]
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            email = user_from_cookie["email"]  
            csrf_token = self.request.get("dontCSRFme")
            ref_name = cgi.escape(self.request.get("reference_name"))
            ref_description = cgi.escape(self.request.get("reference_description"))
            ref_url = cgi.escape(self.request.get("reference_url"))
            ref_type = cgi.escape(self.request.get("reference_type"))
            topic = ndb.Key(urlsafe=topic_key).get()
            
            if topic and ref_name and ref_url and ref_type and self.check_csrf_token(csrf_token, user_name, email):
                reference = Reference(parent=ndb.Key(urlsafe=topic_key),
                                      name = ref_name, 
                                      description = ref_description,
                                      url = ref_url,
                                      ref_type = ref_type,
                                      creator = ndb.Key(urlsafe=user_from_cookie["key"]),
                                      up_votes = 0,
                                      down_votes = 0,
                                      up_voted_by = [],
                                      down_voted_by = [])
                if user_key in topic.admins or user_key == topic.creator:
                    reference.by_member = False
                else:
                    reference.by_member = True
                    
                reference.put()
                self.print_json({"status": "ok", "key": reference.key.urlsafe()})
                return

        self.print_json({"status": "error"})
        return
            
            
class ReferencePage(BaseHandler):
    def get(self, topic_key, reference_key):
        if not self.is_logged_in():
            self.redirect('/topics/%s' % topic_key)
            return
        user_from_cookie = self.session.get("user")
        name = user_from_cookie["name"]
        email = user_from_cookie["email"]
        csrf_token = self.generate_csrf_token(name, email)
        reference = ndb.Key(urlsafe=reference_key).get()
        topic = ndb.Key(urlsafe=topic_key).get()
        user_key = ndb.Key(urlsafe=user_from_cookie["key"])
         
        
        can_delete = (user_key == reference.creator or user_key == topic.creator or user_key in topic.admins )

        if reference and topic.is_public or (user_key in topic.admins or user_key == topic.creator):
            creator = reference.creator.get()
            if creator:
                self.render("reference_page.html", 
                            reference=reference,
                            csrf_token =  csrf_token,
                            user_profile_pic = user_from_cookie["profile_pic"],
                            creator_name = creator.name,
                            can_delete = can_delete,
                            topic = topic)
            return
        self.redirect('/topics/%s' % topic.key.urlsafe())
        return
    
    def post(self, topic_key, reference_key):
        if self.is_logged_in:
            user_from_cookie = self.session.get("user")
            name = user_from_cookie["name"]
            email = user_from_cookie["email"]
            csrf_token = self.request.get('dontCSRFme')
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            
            if self.check_csrf_token(csrf_token, name, email):
                reference = ndb.Key(urlsafe=reference_key).get()
                topic = ndb.Key(urlsafe=topic_key).get()
                if reference and topic and (user_key == reference.creator or user_key == topic.creator or user_key in topic.admins):
                    ndb.delete_multi(ndb.Query(ancestor=ndb.Key(urlsafe=reference_key)).iter(keys_only = True))
        self.redirect('/topics/%s' % topic_key)

class VoteHandler(BaseHandler):
    def change_voting(self, user_from_cookie, reference_key, up_down = 'up'):
        voter = ndb.Key(urlsafe=user_from_cookie["key"])
        reference = ndb.Key(urlsafe=reference_key).get()
        if reference:
            if up_down == 'up' and voter in reference.up_voted_by:
                reference.up_voted_by.remove(voter)
                reference.up_votes -= 1
                reference.put()
                self.print_json({"status": "ok", "msg": "remove up-vote"})
                return
            elif up_down == 'down' and voter in reference.down_voted_by:
                reference.down_voted_by.remove(voter)
                reference.down_votes -= 1
                reference.put()
                self.print_json({"status": "ok", "msg": "remove down-vote"})
                return
            elif up_down == 'up' and voter in reference.down_voted_by:
                reference.up_votes += 1
                reference.down_votes -= 1
                reference.down_voted_by.remove(voter)
                reference.up_voted_by.append(voter)
                reference.put()
                self.print_json({"status": "ok", "prev": "down"})
                return
            elif up_down == 'down' and voter in reference.up_voted_by:
                reference.up_votes -= 1
                reference.down_votes += 1
                reference.up_voted_by.remove(voter)
                reference.down_voted_by.append(voter)
                reference.put()
                self.print_json({"status": "ok", "prev": "up"})
                return
            elif up_down =='up':
                reference.up_votes += 1
                reference.up_voted_by.append(voter)
                reference.put()
                self.print_json({"status": "ok"})
                return
            else:
                reference.down_votes += 1
                reference.down_voted_by.append(voter)
                reference.put()
                self.print_json({"status": "ok"})
                return
        else:
            self.print_json({"status": "error", "msg": "reference not found"})
            return
        
class UpVote(VoteHandler):
    def post(self, reference_key):
        user_from_cookie = self.session.get("user")
        user_name = user_from_cookie["name"]
        email = user_from_cookie["email"]  
        csrf_token = self.request.get("dontCSRFme") 
        
        if self.is_logged_in() and self.check_csrf_token(csrf_token, user_name, email):
            self.change_voting(user_from_cookie, reference_key)
            
            
class DownVote(VoteHandler):
    def post(self, reference_key):
        user_from_cookie = self.session.get("user")
        user_name = user_from_cookie["name"]
        email = user_from_cookie["email"]  
        csrf_token = self.request.get("dontCSRFme") 
        
        if self.is_logged_in() and self.check_csrf_token(csrf_token, user_name, email):
            self.change_voting(user_from_cookie, reference_key, up_down = 'down')
            return
                    
class TopicSearchPage(BaseHandler):
    def get(self):
        if self.is_logged_in():
            self.render('topic_search.html')
        return
    
class TopicSearchQuery(BaseHandler):
    
    def determine_score(self, query_keywords, topic_entity):
        score = 0
        for keyword in query_keywords:
            if keyword.lower() in topic_entity.keywords:
                score += 10
        if topic_entity.in_groups:
            score *= (1.15 * topic_entity.in_groups)
        if topic_entity.in_authorized_groups:
            score *= (1.30 * topic_entity.in_authorized_groups)
        return (topic_entity, score)
    
    
    
    
    def get(self):
        query_keywords = self.request.get("query").split(" ")
        qry = Topic.query(Topic.keywords == query_keywords[0].lower())
        search_results = []
        return_json = {"result": []}
        
        if not self.request.get('query'):
            self.print_json(return_json)
            return
        for keyword in query_keywords[1:]:
            if keyword:
                qry.filter(ndb.OR(Topic.keywords == keyword.lower()))
        qry.filter(ndb.AND(Topic.is_public == True))
        matched_entities = qry.fetch(None)
        
        for entity in matched_entities:
            search_results.append(self.determine_score(query_keywords, entity))
        
        search_results.sort(key = lambda result: result[1])
        
        for result in search_results:
            tmp_dict = { "topic_name": result[0].name,
                        "topic_url" : "/topics/%s" % result[0].key.urlsafe(),
                        "in_groups" : result[0].in_groups
                        }
            tmp_description = self.get_number_of_words(result[0].description, 8)
            if tmp_description: tmp_description += " ..."
            tmp_dict["topic_description"] = tmp_description
            
            return_json["result"].append(tmp_dict)
        
        return_json["result"].reverse()
        self.print_json(return_json)
        return

    
class GroupPage(BaseHandler):

    def get(self, group_key):
        is_logged_in = self.is_logged_in()
        group = ndb.Key(urlsafe=group_key).get()
        if group:
            group = ndb.Key(urlsafe=group_key).get()
            csrf_token = ""
            group_creator = group.creator.get()
            group_creator_name = group_creator.name
            user_profile_pic = ""
            csrf_token = ""
            user_key = ""
            
            if is_logged_in:
                user_from_cookie = self.session.get("user")
                user_profile_pic = user_from_cookie["profile_pic"]
                user_key = ndb.Key(urlsafe=user_from_cookie["key"])
                email = user_from_cookie["email"]
                name = user_from_cookie["name"]
                csrf_token = self.generate_csrf_token(name, email)
                
                
            admin_topic_list = []
            user_topic_list = []
            admin_tasks = []
            admin_events = []
            member_tasks = []
            member_events = []
            school = []
            
            
            for topic in list(reversed(group.admin_topics))[:5]:
                topic = topic.get()
                if topic:
                    admin_topic_list.append(topic)
            
            for topic in list(reversed(group.user_topics))[:5]:
                topic = topic.get()
                if topic:
                    user_topic_list.append(topic)
                    
            
                
            if group.is_authorized:
                school = group.key.parent().get()
                    
            admin_tasks, member_tasks = self.get_tasks_or_events(group_key, n=5)
            admin_events, member_events = self.get_tasks_or_events(group_key, get_events=True, n=5)
                    
            self.render("group_page.html", 
                        group=group, 
                        admin_topic_list = admin_topic_list,
                        user_topic_list = user_topic_list,
                        user_profile_pic = user_profile_pic,
                        csrf_token = csrf_token,
                        admin_tasks = admin_tasks,
                        member_tasks = member_tasks,
                        admin_events = admin_events,
                        member_events = member_events,
                        user_key = user_key,
                        school = school,
                        url = self.request.url,
                        group_creator_name = group_creator_name,
                        meta_group_description = self.get_number_of_words(group.description, n=25, add_points=True),
                        is_logged_in = is_logged_in)
            return
        self.redirect('/')   



class CommentHandler(BaseHandler):
    def get_comments(self, key):
        if not self.is_logged_in: self.redirect('/')
        cache = {}
        return_dict = {"comments": []}
        oldest_shown = self.request.get('oldest')
        if self.is_logged_in():
            qry = Comment.query(ancestor=ndb.Key(urlsafe = key)).order(-Comment.updated)
        
        if oldest_shown: 
                oldest_shown_comment = ndb.Key(urlsafe=oldest_shown).get()
                if oldest_shown_comment:
                    qry = ndb.gql("SELECT * FROM Comment WHERE ANCESTOR IS :1 AND updated < :2 ORDER BY updated DESC", 
                                  ndb.Key(urlsafe = key), oldest_shown_comment.updated)
                else:
                    self.print_json({"status":"error", "msg":"comment not found"})
            
        comments = qry.fetch(5)
        if comments:
            comments.reverse()
        for comment in comments:
            if comment.creator in cache:
                comment_dict = {"creator_name": cache[comment.creator].name,
                                "creator_key": comment.creator.urlsafe(),
                                "comment_content": comment.content,
                                "comment_key": comment.key.urlsafe(),
                                "creator_pic": self.get_active_profile_image(cache[comment.creator])}
                return_dict["comments"].append(comment_dict)
                 
            else:
                creator = comment.creator.get()
                cache[comment.creator] = creator
                comment_dict = {"creator_name": creator.name,
                                "creator_key": comment.creator.urlsafe(),
                                "comment_content": comment.content,
                                "comment_key": comment.key.urlsafe(),
                                "creator_pic": self.get_active_profile_image(creator)}
                return_dict["comments"].append(comment_dict)
        self.print_json(return_dict)
        return
    
    def add_comment(self, key, urlsafe=True):
        user_from_cookie = self.session.get("user")
        user_name = user_from_cookie["name"]
        email = user_from_cookie["email"]  
        csrf_token = self.request.get("dontCSRFme")
        comment_content = cgi.escape(self.request.get("comment_content")).replace('\n', '<br />')
        
        if comment_content and self.is_logged_in() and self.check_csrf_token(csrf_token, user_name, email):
            if urlsafe:
                entity = ndb.Key(urlsafe=key).get()
                if not entity:
                    self.print_json({"status": "error", "msg": "Entity not found"})
                    return
            comment = Comment(parent = ndb.Key(urlsafe=key),
                              content = comment_content,
                              creator = ndb.Key(urlsafe=user_from_cookie["key"]))
            comment.put()
            
            self.print_json({"status":"ok"})
            return
        
        self.print_json({"status":"error"})
        return
        
class AddReferenceComment(CommentHandler):
    def post(self, reference_key):
        new_key = ndb.Key(Reference, ndb.Key(urlsafe=reference_key).id())
        self.add_comment(new_key.urlsafe(), urlsafe=False)
        return
    
class GetReferenceComments(CommentHandler):
    def get(self, reference_key):
        new_key = ndb.Key(Reference, ndb.Key(urlsafe=reference_key).id())
        self.get_comments(new_key.urlsafe())
        return
    
class AddEventComment(CommentHandler):
    def post(self, event_key):
        new_key = ndb.Key(Event, ndb.Key(urlsafe=event_key).id())
        self.add_comment(new_key.urlsafe(), urlsafe=False)
        return
    
class GetEventComments(CommentHandler):
    def get(self, event_key):
        new_key = ndb.Key(Event, ndb.Key(urlsafe=event_key).id())
        self.get_comments(new_key.urlsafe())
        return
    
class AddTaskComment(CommentHandler):
    def post(self, task_key):
        new_key = ndb.Key(Task, ndb.Key(urlsafe=task_key).id())
        self.add_comment(new_key.urlsafe(), urlsafe=False)
        return
    
class GetTaskComments(CommentHandler):
    def get(self, task_key):
        new_key = ndb.Key(Task, ndb.Key(urlsafe=task_key).id())
        self.get_comments(new_key.urlsafe())
        return
    
    
class GetGroupComments(CommentHandler):
    def get(self, group_key):
        self.get_comments(group_key)
        return
    
class AddGroupComment(CommentHandler):
    def post(self, group_key):
        self.add_comment(group_key)
        return

class GetTopicComments(CommentHandler):
    def get(self, topic_key):
        self.get_comments(topic_key)
        return
    
class AddTopicComment(CommentHandler):
    def post(self, topic_key):
        self.add_comment(topic_key)
        return

class GetTasks(BaseHandler):

    pass       
        
class SettingsPage(BaseHandler):
    def get(self):
        user_from_cookie = self.session.get("user")
        if self.is_logged_in():
            groups = Group.query(Group.admins == ndb.Key(urlsafe=user_from_cookie["key"])).fetch(None)
            topics = Topic.query(Topic.admins == ndb.Key(urlsafe=user_from_cookie["key"])).fetch(None)
            name = user_from_cookie["name"]
            email = user_from_cookie["email"]
            csrf_token = self.generate_csrf_token(name, email)
            user = ndb.Key(urlsafe=user_from_cookie["key"]).get()
            self.render("settings_page.html",
                        csrf_token=csrf_token,
                        user = user,
                        groups = groups,
                        topics = topics)
            return
        self.redirect('/')
        
class DeleteData(BaseHandler):
    
    
    def delete_user_data(self, user_key):
        self.response.set_cookie('session', '')

    def post(self):
        if not self.is_logged_in(): 
            self.redirect('/')
            return
        user_from_cookie = self.session.get('user')
        user_name = user_from_cookie["name"]
        user_email = user_from_cookie["email"]
        csrf_token = self.request.get("csrf_token")
        service = self.request.get('service')
        
        if service and self.is_logged_in() and self.check_csrf_token(csrf_token, user_name, user_email):
            self.response.set_cookie('session', '')
            
            
            if service == "all":
                #ndb.Key(urlsafe=user_from_cookie["key"]).delete()
                user = ndb.Key(urlsafe=user_from_cookie["key"]).get()
                user.email = ""
                user.password = ""
                user.user_active_pic = None
                user.put()
                self.logout()
                self.print_json({"status": "ok"})
                return
            
            user = ndb.Key(urlsafe=user_from_cookie["key"]).get()
            if service == "google":
                #if not user.fb_uid and not user.password:
                    #User had nothing connected but Google
                    #self.delete_user_data(urlsafe=user_from_cookie["key"])
                    #self.print_json({"status": "ok"})
                    #return
                user.google_profile_url = None
                user.google_user_id = None
                user.google_profile_pic_url = None
                user.google_access_token = None
                if user.active_pic != "facebook":
                    user.active_pic = "no"
                user.put()
                self.print_json({"status": "ok"})
                return
            elif service == "facebook":
                #if not user.google_user_id and not user.password:
                    #User had nothing connected but Facebook
                    #self.delete_user_data(urlsafe=user_from_cookie["key"])
                    #self.print_json({"status": "ok"})
                    #return
                
                user.fb_profile_url = None
                user.fb_uid = None
                user.fb_access_token = None
                if user.active_pic == "facebook":
                    user.active_pic = "no"
                user.put()
                self.print_json({"status": "ok"})
                return
        else:
            self.error(404)

class UpdateProfilePic(BaseHandler):

    def post(self):
        user_from_cookie = self.session.get('user')
        if self.is_logged_in():
            possible_pics = ["facebook", "google", "no"]
            user_name = user_from_cookie["name"]
            user_email = user_from_cookie["email"]
            checked_pic = self.request.get('checked_pic')
            csrf_token = self.request.get('csrf_token')
            if checked_pic in possible_pics and self.check_csrf_token(csrf_token, user_name, user_email):
                user = ndb.Key(urlsafe=user_from_cookie["key"]).get()
                if user:
                    user.active_pic = checked_pic
                    user.put()
                    self.set_session(user)
                    self.print_json({"status": "succesful"})
                    return

class EmailSignUp(BaseHandler):
    def post(self):
    
        forename = cgi.escape(self.request.get("forename"))
        surname = cgi.escape(self.request.get("surname"))
        name = forename + " " + surname
        pw = self.request.get("password")
        pw_confirm = self.request.get("confirm_password")
        email = cgi.escape(self.request.get("email"))
        gender = self.request.get("gender")
        possible_genders = ["male", "female"]
        
        if forename and surname and self.is_valid_password(pw) and pw == pw_confirm and self.is_valid_email(email) and gender in possible_genders: 
            if ndb.gql("SELECT * FROM User WHERE email = :1", email).get():
                self.print_json({"status": "error", "msg": "A user with this email address already exists."})
            else:
                pw_salt = self.make_salt()
                confirm_email_code = self.make_salt(30)
                hashed_pw_w_salt = pw_salt + hashlib.sha512(unidecode(email) + pw_salt + unidecode(name) + unidecode(pw)).hexdigest() 
                user = User(name = name,
                            password = hashed_pw_w_salt,
                            gender = gender,
                            email = email,
                            confirm_email_hash = confirm_email_code,
                            first_name = forename,
                            second_name = surname)
                user.put()
                confirm_url = self.request.host_url + '/confirm/' + user.key.urlsafe() + '?s=' + confirm_email_code
                #name, email, pw, gender
                #TODO: send email
                mail.send_mail("noreply@gcdc2013-oxys.appspotmail.com",
                      email,
                      "Welcome to Oxys",
                      "Welcome to Oxys %s,\nverify your email address by clicking on the link below:\n%s" % (forename, confirm_url))
                self.print_json({"status": "ok"})
        else:
            self.print_json({"status": "error", "msg": "Please reassure that your entered data is correct."})
        
class EmailSignIn(BaseHandler):
    def post(self):
        email = self.request.get('sign-in-email')
        password = self.request.get('sign-in-password')
        if self.is_valid_email(email):
            
            user = ndb.gql('SELECT * FROM User WHERE email = :1', email).get()
            if not user:
                
                self.print_json({"status": "error", "msg": "The email - password combination is wrong."})
                return
            elif user and not user.password:
                
                self.print_json({"status": "error", "msg": "There is no password set for this account. Sign in with Facebook or Google."})
                return
            else:
                
                user_pw_salt = user.password[:5]
                
                if user.confirm_email_hash:
                    #User has yet to confirm his email
                    self.print_json({"status": "error", "msg": "Please confirm your email address first."})
                    return
                
                elif (user_pw_salt + hashlib.sha512(unidecode(email) + user_pw_salt + unidecode(user.name) + unidecode(password)).hexdigest()) == user.password:
                    self.set_session(user)
                    self.print_json({"status": "ok"})
                    return
                else:
                    self.print_json({"status": "error", "msg": "The email - password combination is wrong."})
                    return
        else: self.print_json({"status": "error", "msg": "Thats not a valid email address!"})

class ConfirmEmail(BaseHandler):
    def get(self, user_key):
        user = ndb.Key(urlsafe=user_key).get()
        token = self.request.get('s')
        if token == user.confirm_email_hash:
            user.confirm_email_hash = None
            user.put()
        self.redirect('/?action=email_confirm')
        return

class JoinGroup(BaseHandler):
    def post(self, group_key):
        if self.is_logged_in():
            user_from_cookie = self.session.get('user')
            name = user_from_cookie["name"]
            email = user_from_cookie["email"]
            csrf_token = self.request.get('csrf_token')
            if self.check_csrf_token(csrf_token, name, email):
                group = ndb.Key(urlsafe=group_key).get()
                if group:
                    #two cases here: group is public, everybody can join.
                    #                group is not public, members need to be approved
                    if group.is_public:
                        group.members.append(ndb.Key(urlsafe=user_from_cookie["key"]))
                        group.put()
                        self.print_json({"status": "ok"})
                        return
                    else:
                        group.awaiting_members.append(ndb.Key(urlsafe=user_from_cookie["key"]))
                        group.put()
                        self.print_json({"status": "ok", "msg": "You will be added to the group as soon as an administrator approves."})
                        return

class MemberRemoval():
    def remove_from(self, group_key, remove_from="members"):
        if self.is_logged_in():
            user_from_cookie = self.session.get('user')
            user_name = user_from_cookie["name"]
            user_email = user_from_cookie["email"]
            csrf_token = self.request.get('dontCSRFme')
            to_remove = self.request.get_all('user')
            
            if to_remove and self.check_csrf_token(csrf_token, user_name, user_email):
                group = ndb.Key(urlsafe=group_key).get()
                if group and ndb.Key(urlsafe=user_from_cookie["key"]) in group.admins:
                    
                    if remove_from == "members":
                        for member in to_remove:
                            group.members.remove(ndb.Key(urlsafe=member))
                            
                    if remove_from == "approval":
                        for user in to_remove:
                            group.awaiting_members.remove(ndb.Key(urlsafe=member))
                    group.put()
                    return 
                    
                    
class ApprovePage(BaseHandler, MemberRemoval):
    def get(self, group_key):
        if self.is_logged_in():
            user_from_cookie = self.session.get('user')
            group = ndb.Key(urlsafe=group_key).get()
            name = user_from_cookie["name"]
            email = user_from_cookie["email"]
            csrf_token = self.generate_csrf_token(name, email)
            
            if group and ndb.Key(urlsafe=user_from_cookie["key"]) in group.admins:
                approval_list = []
                for user in group.awaiting_members:
                    approval_list.append(user.get())
                self.render("approval_page.html",
                            approval_list=approval_list,
                            csrf_token = csrf_token)
                
            else:
                self.redirect("/groups/%s" % group_key)
    
    def post(self, group_key):
        user_from_cookie = self.session.get('user')
        name = user_from_cookie["name"]
        email = user_from_cookie["email"]
        csrf_token = self.request.get("dontCSRFme")
        checked_users = self.request.get_all("user")
        remove = self.request.get('delete')
        
        if checked_users and self.is_logged_in() and self.check_csrf_token(csrf_token, name, email):
            
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            group = ndb.Key(urlsafe=group_key).get()
            if group and user_key in group.admins:
                for user in checked_users:
                    user = ndb.Key(urlsafe=user)
                    if user in group.awaiting_members and user not in group.members:
                        if not remove:
                            group.members.append(user)
                        group.awaiting_members.remove(user)
                
                group.put()
        
        self.redirect('/groups/%s' % group_key )
        return
            
class EventPage(BaseHandler):
    def get(self, group_key, event_key):
        if self.is_logged_in():
            user_from_cookie = self.session.get('user')
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            name = user_from_cookie['name']
            email = user_from_cookie['email']
            csrf_token = self.generate_csrf_token(name, email)
            
            event = ndb.Key(urlsafe=event_key).get()
            group = ndb.Key(urlsafe=group_key).get()
            
            
            
            if event and group:    
                creator = event.creator.get()
                can_delete = (event.creator == user_key or (user_key == group.creator or user_key in group.admins))
                self.render("event_page.html", 
                            event = event,
                            creator = creator,
                            user_profile_pic = self.session.get('user')["profile_pic"],
                            csrf_token = csrf_token,
                            can_delete = can_delete,
                            group=group)
                return
        self.redirect('/groups/%s' % group_key)
        return
    
    def post(self, group_key, event_key):
        if self.is_logged_in:
            user_from_cookie = self.session.get("user")
            name = user_from_cookie["name"]
            email = user_from_cookie["email"]
            csrf_token = self.request.get('dontCSRFme')
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            
            if self.check_csrf_token(csrf_token, name, email):
                event = ndb.Key(urlsafe=event_key).get()
                group = ndb.Key(urlsafe=group_key).get()
                if event and group and (user_key == event.creator or user_key == group.creator or user_key in group.admins):
                    ndb.delete_multi(ndb.Query(ancestor=ndb.Key(urlsafe=event_key)).iter(keys_only = True))
        self.redirect('/groups/%s' % group_key)
        
class TaskPage(BaseHandler):
    def get(self, group_key, task_key):
        if self.is_logged_in():
            user_from_cookie = self.session.get('user')
            name = user_from_cookie['name']
            email = user_from_cookie['email']
            csrf_token = self.generate_csrf_token(name, email)
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            
            task = ndb.Key(urlsafe=task_key).get()
            group = ndb.Key(urlsafe=group_key).get()
            
            
            if task and group:
                can_delete = (user_key == task.creator or (user_key == group.creator or user_key in group.admins))
                creator = task.creator.get()
                self.render("task_page.html", 
                            task = task,
                            creator = creator,
                            user_profile_pic = self.session.get('user')["profile_pic"],
                            csrf_token = csrf_token,
                            can_delete = can_delete,
                            group = group)
                return
        self.redirect('/groups/%s' % group_key)
        return
    
    def post(self, group_key, task_key):
        if self.is_logged_in:
            user_from_cookie = self.session.get("user")
            name = user_from_cookie["name"]
            email = user_from_cookie["email"]
            csrf_token = self.request.get('dontCSRFme')
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            
            if self.check_csrf_token(csrf_token, name, email):
                task = ndb.Key(urlsafe=task_key).get()
                group = ndb.Key(urlsafe=group_key).get()
                if task and group and (user_key == task.creator or user_key == group.creator or user_key in group.admins):
                    ndb.delete_multi(ndb.Query(ancestor=ndb.Key(urlsafe=task_key)).iter(keys_only = True))
        self.redirect('/groups/%s' % group_key)
        
        
class ServeImage(BaseHandler):
    def get(self, user_key):
        
        user = ndb.Key(urlsafe=user_key).get()
        if user:
            self.response.headers['Content-Type'] = 'image/jpeg'
            self.response.out.write(resize(user.fb_profile_pic, 50, 50))
            #self.response.out.write((user.fb_profile_pic))
            return
        else:
            self.error(404)


            
class MemberPage(BaseHandler, MemberRemoval):
    
    def make_admin(self, group_key):
        if self.is_logged_in():
            group = ndb.Key(urlsafe=group_key).get()
            user_from_cookie = self.session.get('user')
            user_name = user_from_cookie["name"]
            user_email = user_from_cookie["email"]
            user_key = ndb.Key(urlsafe=user_from_cookie["key"]) #key of submitter
            csrf_token = self.request.get('dontCSRFme')
            add_to_admin_users = self.request.get_all('user')
            
            if add_to_admin_users and group and self.check_csrf_token(csrf_token, user_name, user_email) and (user_key in group.admins or user_key == group.creator):
                
                for user in add_to_admin_users:
                    user_key = ndb.Key(urlsafe=user)
                    if user_key in group.members and not user_key in group.admins:
                        group.members.remove(user_key)
                        group.admins.append(user_key)
                group.put()
            
            self.redirect('/groups/%s' % group_key)
            return
                        
    
    def get(self, group_key):
        
        group = ndb.Key(urlsafe=group_key).get()
        user_from_cookie = self.session.get('user')
        user_name = user_from_cookie["name"]
        user_email = user_from_cookie["email"]
        csrf_token = self.generate_csrf_token(user_name, user_email)
        
        if user_from_cookie:
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
        
        if group and self.is_logged_in() and user_key in group.members or user_key in group.admins:
            member_list = []
            admin_list = []
            
            
            for member in group.members:
                member_list.append(member.get())
            for admin in group.admins:
                admin_list.append(admin.get())
            
            #admin_list.append(group.creator.get())
            
            self.render("members_page.html",
                        member_list = member_list,
                        admin_list = admin_list,
                        group = group,
                        user_key = user_key,
                        csrf_token = csrf_token)
            return
        
        self.redirect('/')
        return
        
    def post(self, group_key):
        if self.request.get('make-admin'):
            self.make_admin(group_key)
            return
        else:
            self.remove_from(group_key)
            self.redirect('/')
            return
    

class GroupSettingsPage(GroupPage):
    def get(self, group_urlsafe_key):
        if self.is_logged_in:
            group_key = ndb.Key(urlsafe=group_urlsafe_key)
            user_from_cookie = self.session.get('user')
            user_name = user_from_cookie["name"]
            user_email = user_from_cookie["email"]
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            csrf_token = self.generate_csrf_token(user_name, user_email)
            school = []
            
            group = group_key.get()
            if group and user_key in group.admins:
                parent = group.key.parent()
                if parent:
                    school = group.key.parent().get()
                    
                    
                    #def get_tasks_or_events(self, group_key, get_events=False, return_json=False):
                admin_topic_list = []
                member_topic_list = []
                admin_event_list, member_event_list = self.get_tasks_or_events(group_urlsafe_key, get_events=True)
                admin_task_list, member_task_list = self.get_tasks_or_events(group_urlsafe_key)
                                
                for topic in group.admin_topics:
                    topic = topic.get()
                    if topic:
                        admin_topic_list.append(topic)
                for topic in group.user_topics:
                    topic = topic.get()
                    if topic:
                        member_topic_list.append(topic)

                
                self.render("group_settings_page.html",
                            group = group, 
                            csrf_token = csrf_token,
                            school = school,
                            admin_topic_list = admin_topic_list,
                            member_topic_list = member_topic_list,
                            admin_event_list = admin_event_list,
                            member_event_list = member_event_list,
                            admin_task_list = admin_task_list,
                            member_task_list = member_task_list)
                return
        self.redirect("/groups/%s" % group_urlsafe_key)
        return
    
    def post(self, group_key):
        if self.is_logged_in():
            group = ndb.Key(urlsafe=group_key).get()
            csrf_token = self.request.get('dontCSRFme')
            user_from_cookie = self.session.get('user')
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            user_name = user_from_cookie["name"]
            user_email = user_from_cookie["email"]
            
            if group and self.check_csrf_token(csrf_token, user_name, user_email) and user_key in group.admins:
                
                new_name = self.request.get('group_name')
                new_description = self.request.get('group_description')
                new_is_public = self.request.get('public')
                remove_from_school = self.request.get('remove_school')
                to_remove_admin_topics = self.request.get_all('admin-topic')
                to_remove_member_topics = self.request.get_all('member-topic')
                to_remove_tasks = self.request.get_all('task')
                to_remove_events = self.request.get_all('event')
                
                
                if new_name != group.name:
                    group.name = new_name
                
                if new_description != group.description:
                    group.description = new_description
                
                if group.is_public and not new_is_public:
                    group.is_public = False
                elif not group.is_public and new_is_public:
                    group.is_public = True
                
                if remove_from_school:
                    group.in_school = False
                    
                for topic in to_remove_admin_topics:
                    group.admin_topics.remove(ndb.Key(urlsafe=topic))
                    
                for topic in to_remove_member_topics:
                    group.user_topics.remove(ndb.Key(urlsafe=topic))
                    
                for task in to_remove_tasks:
                    ndb.Key(urlsafe=task).delete()
                    
                for event in to_remove_events:
                    ndb.Key(urlsafe=event).delete()
                
                group.put()
                
        self.redirect('/groups/%s/settings' % group_key)
    
class LeaveGroup(BaseHandler):
    def post(self, group_key):
        if self.is_logged_in:
            user_from_cookie = self.session.get('user')
            user_name = user_from_cookie["name"]
            user_email = user_from_cookie["email"]
            csrf_token = self.request.get('csrf_token')
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            group = ndb.Key(urlsafe=group_key).get()
            
            if group and self.check_csrf_token(csrf_token, user_name, user_email) and (user_key in group.admins or user_key in group.members):
                if user_key in group.members:
                    group.members.remove(user_key)
                    
                elif user_key in group.admins:
                    group.admins.remove(user_key)
                
                group.put()
                self.print_json({"status": "ok"})
                return
        self.redirect('/groups/%s' % group_key)
        return
    
    
class AddToGroupsPage(BaseHandler):
    
    def get(self, topic_key):
        if self.is_logged_in():
            user_from_cookie = self.session.get('user')
            user_name = user_from_cookie["name"]
            user_email = user_from_cookie["email"]
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            csrf_token = self.generate_csrf_token(user_name, user_email)
            topic = ndb.Key(urlsafe=topic_key).get()
            if topic and (topic.is_public or user_key == topic.creator or user_key in topic.admins):
                member_groups = ndb.gql("select * from Group where members = :1", user_key).fetch(None)
                admin_groups =  Group.query(Group.admins == user_key,
                                               ndb.OR(Group.creator == user_key)).fetch(None)
                
                admin_groups = [group for group in admin_groups if ndb.Key(urlsafe=topic_key) not in group.admin_topics]
                member_groups = [group for group in member_groups if (ndb.Key(urlsafe=topic_key) not in group.admin_topics and ndb.Key(urlsafe=topic_key) not in group.user_topics)]
                self.render("add_topic_to_group.html",
                            csrf_token = csrf_token,
                            admin_groups = admin_groups,
                            member_groups = member_groups)
                return
        self.redirect("/topics/topic_key")
        return
    
    def post(self, urlsafe_topic_key):
        if self.is_logged_in:
            csrf_token = self.request.get("dontCSRFme")
            user_from_cookie = self.session.get('user')
            user_name = user_from_cookie["name"]
            user_email = user_from_cookie["email"]
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            to_add_to = self.request.get_all('group')
            topic_key = ndb.Key(urlsafe=urlsafe_topic_key)
            
            
            
            if to_add_to and self.check_csrf_token(csrf_token, user_name, user_email) and topic_key.get():
                
                for group_key in to_add_to:
                    group = ndb.Key(urlsafe=group_key).get()
                    if group:
                        
                        if user_key in group.admins and topic_key not in group.admin_topics:
                            
                            group.admin_topics.append(topic_key)
                            group.put()
                        elif user_key in group.members and topic_key not in group.user_topics:
                            group.user_topics.append(topic_key)
                            group.put()
                            
                            
        self.redirect("/topics/%s" % urlsafe_topic_key)
                            

class ViewAllRef(BaseHandler, ReferenceRanking):
    def view_all_references(self, topic_key, admin_refs=True):
        if self.is_logged_in():
            topic = ndb.Key(urlsafe=topic_key)
            all_refs = []
            if topic:
                if admin_refs:
                    topic_references = Reference.query(Reference.by_member == False, ancestor=topic )
                    #for ref in topic_references:
                     #   logging.error(ref)
                    #  all_refs.append(ref)
                    topic_references.sort( key = lambda reference: reference.created)  
                else:
                    topic_references = Reference.query(Reference.by_member == True, ancestor=topic ).fetch(None)
                    topic_references.sort( key = lambda reference: self.return_score(reference),
                                          reverse = True)
                
                self.render('view_all_refs.html',
                            references = topic_references,
                            admin_refs = admin_refs,
                            topic_key = topic_key)
                return
        self.redirect('/')
                
class ViewMemberRefs(ViewAllRef):
    def get(self, topic_key):
        self.view_all_references(topic_key, admin_refs=False)
        return
class ViewAdminRefs(ViewAllRef):
    def get(self, topic_key):
        self.view_all_references(topic_key)
        return

class ViewAllTopics(BaseHandler):
    def view_all_topics(self, group_key, admin=True):
        if self.is_logged_in():
            group = ndb.Key(urlsafe=group_key).get()
            user_key = ndb.Key(urlsafe=self.session.get('user')["key"])
            fetched_topics = []
            
            if group and (user_key in group.admins or user_key in group.members):
                if admin:
                    group_topics = group.admin_topics
                else:
                    group_topics = group.user_topics
                
                for topic in reversed(group_topics):
                    topic = topic.get()
                    topic.description = self.get_number_of_words(topic.description, 20, add_points=True)
                    fetched_topics.append(topic)
                    
                self.render("view_all_topics.html",
                            topics = fetched_topics,
                            admin = admin)
                return
            
        self.redirect('/groups/%s' % group_key)
    
class ViewAdminTopicsPage(ViewAllTopics):
    def get(self, group_key):
        self.view_all_topics(group_key)
        return
    
class ViewMemberTopicsPage(ViewAllTopics):
    def get(self, group_key):
        self.view_all_topics(group_key, admin=False)
        return

class SlashRedirect(BaseHandler):
    def get(self):
        self.redirect(self.request.url[:-1])
        return
    
class TopicSettingsPage(BaseHandler):
    def get(self, topic_key):
        if self.is_logged_in():
            user_from_cookie = self.session.get('user')
            user_name = user_from_cookie["name"]
            user_email = user_from_cookie["email"]
            csrf_token = self.generate_csrf_token(user_name, user_email)
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            topic = ndb.Key(urlsafe=topic_key).get()
            
            if user_key == topic.creator or user_key in topic.admins:
                
                references = Reference.query(ancestor=ndb.Key(urlsafe=topic_key)).fetch(None)
                admin_refs = []
                member_refs = []
                
                for ref in references:
                    if ref.by_member: member_refs.append(ref)
                    else: admin_refs.append(ref)
                                
                self.render('topic_settings_page.html',
                            topic = topic,
                            csrf_token = csrf_token,
                            formatted_keywords = ' '.join(topic.keywords),
                            admin_refs = admin_refs,
                            member_refs = member_refs)
                return
            
        self.redirect('/topics/%s' % topic_key)
        return
    
    def post(self, topic_key):
        if self.is_logged_in():
            user_from_cookie = self.session.get('user')
            user_name = user_from_cookie["name"]
            user_email = user_from_cookie["email"]
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            topic = ndb.Key(urlsafe=topic_key).get()
            csrf_token = self.request.get('dontCSRFme')
            
            if topic and csrf_token and (user_key == topic.creator or user_key in topic.admins) and self.check_csrf_token(csrf_token, user_name, user_email):
                
                new_name = self.request.get('topic_name')
                new_description = self.request.get('topic_description')
                new_public = self.request.get('public')
                to_delete_refs = self.request.get_all('reference')
                keywords = self.request.get('keywords')
                
                if new_name and new_name != topic.name:
                    topic.name = new_name
                
                if new_description != topic.description:
                    topic.description = new_description
                    
                if new_public:
                    entered_keywords = list(set(keywords.split(' ') + new_name.split(" ")))
                    keywords_for_db = []
                    for w in entered_keywords:
                        if len(w) > 1 and w != " ":
                            keywords_for_db.append(w.lower())
                    topic.keywords = keywords_for_db  
                    topic.is_public = True
                    
                elif not new_public and topic.is_public:
                    topic.keywords = []
                    topic.is_public = False
                    
                for ref in to_delete_refs:
                    ndb.delete_multi(ndb.Query(ancestor=ndb.Key(urlsafe=ref)).iter(keys_only = True))
                    
                topic.put()
        self.redirect('/topics/%s' % topic_key)
        return
        
class ViewTopics(BaseHandler):
    
    def get(self):
        if self.is_logged_in():
            user_from_cookie = self.session.get('user')
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            topics = Topic.query(Topic.creator == user_key, ndb.OR(Topic.admins == user_key)).fetch(None)
            
            for topic in topics:
                topic.description = self.get_number_of_words(topic.description, n=20, add_points=True)
            
            self.render('view_all_topics.html',
                        topics = topics,
                        personal = True)
            return
        
        self.redirect('/')
        return

    
class ViewAllGroups(BaseHandler):
    
    def view_groups(self, admin_or_member):
        if self.is_logged_in():
            user_from_cookie = self.session.get('user')
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            
            if admin_or_member == "admin":
                groups = Group.query(Group.admins == user_key)
                groups.filter(ndb.OR(Group.creator == user_key))
                groups = groups.fetch(None)
                by_admin = True
            else:
                groups = Group.query(Group.members == user_key).fetch(None)
                by_admin = False
            
            for group in groups:
                group.description = self.get_number_of_words(group.description, n=20, add_points = True)
                test = self.get_number_of_words("asdf asdf asdf asdf asdf asd fas fas asdf asd asdf\n asdf asd asdfasdf asdf asdf asdf asdf asdf\n asdf sdf as dfasas fasdf asdf\n asdfa sf asd ass dfasfas fas", n=20, add_points = True)
            
            if groups:
                self.render("view_all_groups.html",
                            groups = groups,
                            admin = by_admin,
                            test = test)
                return
        self.redirect('/')
            
        

class ViewAllAdminGroups(ViewAllGroups):
    def get(self):
        self.view_groups("admin")
        return
    
class ViewAllMemberGroups(ViewAllGroups):
    def get(self):
        self.view_groups("member")
        return
    
    
class LogOut(BaseHandler):
    def get(self):
        self.logout()
        self.redirect('/')
    

class ViewGroups(BaseHandler):
    def get(self):
        if self.is_logged_in():
            user_from_cookie = self.session.get('user')
            user_key = ndb.Key(urlsafe=user_from_cookie["key"])
            
            admin_groups = Group.query(Group.admins == user_key)
            admin_groups.filter(ndb.OR(Group.creator == user_key))
            admin_groups = admin_groups.fetch(None)
            
            member_groups = Group.query(Group.members == user_key).fetch(None)
            
            self.render('my_groups.html',
                        admin_groups = admin_groups,
                        member_groups = member_groups)
            return
            
        self.redirect('/')
        return

class ViewMap(BaseHandler):
    
    def rank(self, school_list):
        given_ranks = {}
        finished_list = []
        current_lowest_ranking = 0
        current_lowest_num_groups = school_list[0][0].num_groups +1 #init the var to make sure its bigger than first element in list
        for school in school_list:
            if school[0].num_groups < current_lowest_num_groups:
                current_lowest_ranking += 1
                current_lowest_num_groups = school[0].num_groups
                finished_list.append((school[0], school[1], current_lowest_ranking))
            elif school[0].num_groups == current_lowest_num_groups:
                finished_list.append((school[0], school[1], current_lowest_ranking))
        return finished_list
            
        
    def remove_numbers(self, string):
        return ''.join([i for i in string if not i.isdigit() and not i == '-'])
    
    def get(self):
        schools = School.query().order(-School.num_groups).fetch(10)
        school_list = []
        for school in schools:
            school_list.append((school, self.remove_numbers(school.key.urlsafe())))
        school_list = self.rank(school_list)
        self.render("map.html", schools=school_list)
    
app = webapp2.WSGIApplication([('/', HomePage),
                               (r'.+\/', SlashRedirect),
                               ('/map', ViewMap),
                               ('/signup', EmailSignUp),
                               ('/logout', LogOut),
                               ('/viewAdminTasks', ViewAllAdminTasks),
                               ('/viewMemberTasks', ViewAllMemberTasks),
                               ('/viewAdminEvents', ViewAllAdminEvents),
                               ('/viewMemberEvents', ViewAllMemberEvents),
                               ('/viewTopics', ViewTopics),
                               ('/viewGroups', ViewGroups),
                               ('/viewAdminGroups', ViewAllAdminGroups),
                               ('/viewMemberGroups', ViewAllMemberGroups),
                               ('/schoolSearch', SchoolSearch),
                               ('/emailSignIn', EmailSignIn),
                               ('/fblogin', FacebookLogin),
                               ('/channel.html', FBChannelFile),
                               ('/gplogin', GooglePlusSignIn),
                               ('/createGroup', CreateGroup),
                               ('/topics/searchQuery', TopicSearchQuery),
                               ('/getGroups', GetGroups),
                               ('/settings', SettingsPage),
                               ('/deleteData', DeleteData),
                               ('/updateProfilePic', UpdateProfilePic),
                               (r'/confirm/([a-zA-Z0-9-_]+)', ConfirmEmail),
                               (r'/groups/([a-zA-Z0-9-_]+)', GroupPage),
                               (r'/groups/([a-zA-Z0-9-_]+)/join', JoinGroup),
                               (r'/groups/([a-zA-Z0-9-_]+)/approve', ApprovePage),
                               (r'/groups/([a-zA-Z0-9-_]+)/getComments', GetGroupComments),
                               (r'/groups/([a-zA-Z0-9-_]+)/addComment', AddGroupComment),
                               (r'/groups/([a-zA-Z0-9-_]+)/members', MemberPage),
                               (r'/groups/([a-zA-Z0-9-_]+)/settings', GroupSettingsPage),
                               (r'/groups/([a-zA-Z0-9-_]+)/events/([a-zA-Z0-9-_]+)', EventPage),
                               (r'/groups/([a-zA-Z0-9-_]+)/tasks/([a-zA-Z0-9-_]+)', TaskPage),
                               (r'/topics/([a-zA-Z0-9-_]+)', TopicPage),
                               (r'/topics/([a-zA-Z0-9-_]+)/add', ReferenceAddPage),
                               (r'/groups/([a-zA-Z0-9-_]+)/add', GroupAddPage),
                               (r'/groups/([a-zA-Z0-9-_]+)/addEvent', AddEvent),
                               (r'/groups/([a-zA-Z0-9-_]+)/addTask', AddTask),
                               (r'/groups/([a-zA-Z0-9-_]+)/leave', LeaveGroup),
                               (r'/groups/([a-zA-Z0-9-_]+)/getTasks', GetTasks),
                               (r'/topics/([a-zA-Z0-9-_]+)/addRef', AddReference),
                               (r'/topics/([a-zA-Z0-9-_]+)/references/([a-zA-Z0-9-_]+)', ReferencePage),
                               (r'/topics/([a-zA-Z0-9-_]+)/getComments', GetTopicComments),
                               (r'/topics/([a-zA-Z0-9-_]+)/addComment', AddTopicComment),
                               (r'/topics/([a-zA-Z0-9-_]+)/addToGroups', AddToGroupsPage),
                               (r'/topics/([a-zA-Z0-9-_]+)/viewMemberRefs', ViewMemberRefs),
                               (r'/topics/([a-zA-Z0-9-_]+)/viewAdminRefs', ViewAdminRefs),
                               (r'/topics/([a-zA-Z0-9-_]+)/topicSettings', TopicSettingsPage),
                               (r'/references/([a-zA-Z0-9-_]+)/up', UpVote),
                               (r'/references/([a-zA-Z0-9-_]+)/down', DownVote),
                               (r'/references/([a-zA-Z0-9-_]+)/addComment', AddReferenceComment),
                               (r'/references/([a-zA-Z0-9-_]+)/getComments', GetReferenceComments),
                               (r'/tasks/([a-zA-Z0-9-_]+)/addComment', AddTaskComment),
                               (r'/tasks/([a-zA-Z0-9-_]+)/getComments', GetTaskComments),
                               (r'/events/([a-zA-Z0-9-_]+)/addComment', AddEventComment),
                               (r'/events/([a-zA-Z0-9-_]+)/getComments', GetEventComments),
                               (r'/groups/([a-zA-Z0-9-_]+)/addTopic', AddToGroupPage),
                               (r'/groups/([a-zA-Z0-9-_]+)/createTopic', CreateTopic),
                               (r'/groups/([a-zA-Z0-9-_]+)/viewAdminTopics', ViewAdminTopicsPage),
                               (r'/groups/([a-zA-Z0-9-_]+)/viewMemberTopics', ViewMemberTopicsPage),
                               ('/users/([a-zA-Z0-9-_]+)/serveImage', ServeImage)
                               ], config=config, debug = True)