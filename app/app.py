import bcrypt as bcrypt
import flask
from flask import Flask, render_template, request, redirect, session, url_for
from pymongo import MongoClient
from datetime import datetime
from twython import Twython
from instagram import client
from linkedin import linkedin
import dateutil.parser
import uuid
import json

app = Flask(__name__)

# connection to mongoDB
mongoClient = MongoClient('mongodb://localhost:27017/')
db = mongoClient.testProject
t_user = db.T_USER
t_social_user_details = db.T_SOCIAL_USER_DETAILS
t_posts = db.T_POSTS


# Facebook app details
FB_APP_KEY = ''
FB_APP_SECRET = ''


# Twitter App Details
consumer_key = ''
consumer_secret = ''


# Instagram App Details
client_id = ''
client_secret = ''


# LinkedIn App Details
li_client_id = ''
li_client_secret = ''


@app.route("/")
def main():
    return render_template('index.html')


@app.route('/showSignUp')
def show_sign_up():
    return render_template('signup.html')


@app.route('/showLogIn')
def show_log_in():
    return render_template('logIn.html')


@app.route('/signUp', methods=['POST', 'GET'])
def sign_up():
    username = request.form['inputUsername']
    email = request.form['inputEmail']
    password = request.form['inputPassword']

    if request.method == 'POST':
        if username and email and password:
            existing_user = t_user.find_one({'username': username})
            if existing_user is None:
                hashpass = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                new_user = {
                        '_id': uuid.uuid1().hex,
                        'username': username,
                        'email_id': email,
                        'password': hashpass
                    }
                t_user.insert(new_user)
                session['username'] = username
                return "registered successfully"
            return "username already exists"
        return "success"
    return render_template('signup.html')


@app.route('/logIn', methods=['POST'])
def log_in():
    print "ewewew"
    email = request.form['inputEmail']
    password = request.form['inputPassword']

    login_user = t_user.find_one({'email_id': email})
    if login_user:
        if bcrypt.hashpw(password.encode('utf-8'), login_user['password'].encode('utf-8')) == login_user['password'].encode('utf-8'):
            session['username'] = login_user['username']
            return "logged in successfully"

    return "Invalid username/password combination"


@app.route('/facebook/saveUserDetails', methods=['POST'])
def save_facebook_user_details():
    user = json.loads(request.form['data'])
    print "saving user"
    print user
    if t_social_user_details.find({'user_fb_id': user['id']}).count() == 0:
        if user.get('email') is None:
            user['email'] = ""
        if user.get('gender') is None:
            user['gender'] = ""

        user_details = {'_id': uuid.uuid1().hex,
                        'user_fb_id': user['id'],
                        'name': user['name'],
                        'email_id': user['email'],
                        'gender': user['gender'],
                        'account_type': 'facebook',
                        'sys_created_date': datetime.now()}

        t_social_user_details.insert(user_details)
        print "success"
        return "success"
    else:
        return "existed"


@app.route('/facebook/saveAllPosts', methods=['POST'])
def save_all_facebook_posts():
    posts = json.loads(request.form['data'])
    user_data = posts['data']
    print "saving fb posts"
    for x in user_data:
        if t_posts.find({'post_id': x['id']}).count() == 0:
            if x.get('message') is None:
                x['message'] = ""
            if x.get('story') is None:
                x['story'] = ""
            if x.get('link') is None:
                x['link'] = ""
            if x.get('picture') is None:
                x['picture'] = ""

            post_details = {'_id': uuid.uuid1().hex,
                            'user_id': x['id'].split("_")[0],
                            'post_id': x['id'],
                            'post_type': x['type'],
                            'story': x['story'],
                            'link': x['link'],
                            'message': x['message'],
                            'created_date': dateutil.parser.parse(x['created_time']),
                            'sys_created_date': datetime.now()}

            t_posts.insert(post_details)
            print "new post"
    return "success"


@app.route('/facebook/getAllPosts', methods=['GET'])
def get_all_facebook_posts():
    result = []
    if t_posts.find().count() != 0:
        posts = t_posts.find()
        for post in posts:
            result.append(post)
    else:
        return "fail"
    return flask.jsonify(items=result)


@app.route('/facebook/getAllPostsByDate/<created_date>', methods=['GET'])
def get_all_facebook_posts_by_date(created_date):
    if t_posts.find({'created_time': created_date}).count() > 0:
        posts = t_posts.find({'created_time': created_date})
        return posts


@app.route('/twitter/Oauth', methods=['POST'])
def twitter_authorization():
    t = Twython(consumer_key, consumer_secret)
    auth = t.get_authentication_tokens(callback_url='http://localhost:5000/twitter/verifyAccount')

    global oauth_token_secret
    oauth_token_secret = auth['oauth_token_secret']
    return auth['auth_url']


@app.route('/twitter/verifyAccount', methods=['GET'])
def twitter_account_verify():
    oauth_token = request.args.get('oauth_token')
    oauth_verifier = request.args.get('oauth_verifier')

    t = Twython(consumer_key, consumer_secret, oauth_token, oauth_token_secret)
    auth_token = t.get_authorized_tokens(oauth_verifier)

    access_token = auth_token['oauth_token']
    access_token_secret = auth_token['oauth_token_secret']

    global twitter
    twitter = Twython(consumer_key, consumer_secret, access_token, access_token_secret)

    return render_template('index.html')


@app.route('/twitter/saveUserDetails')
def save_twitter_user_details():
    user = twitter.show_user(screen_name='rahulshar5885')
    print user
    if t_social_user_details.find({'user_twitter_id': user['id_str']}).count() == 0:
        user_details = {'_id': uuid.uuid1().hex,
                        'user_twitter_id': user['id'],
                        'username': user['screen_name'],
                        'name': user['name'],
                        'account_type': 'twitter',
                        'sys_created_date': datetime.now()}

        t_social_user_details.insert(user_details)
        print "new user"
        return "new user registered"
    else:
        print "existing user"
        return "existing user"


@app.route('/twitter/saveAllTweets')
def save_all_twitter_posts():
    posts = twitter.get_user_timeline(screen_name='rahulshar5885', count=200)

    for x in posts:
        print x
        if t_posts.find({'post_id': x['id_str']}).count() == 0:
            post_details = {'_id': uuid.uuid1().hex,
                            'user_id': x['user']['id_str'],
                            'post_id': x['id_str'],
                            'message': x['text'],
                            'created_date': dateutil.parser.parse(x['created_at']),
                            'sys_created_date': datetime.now()}

            t_posts.insert(post_details)
            print "new Tweet"
        else:
            print "old tweet"
    return "success"


@app.route('/instagram/Oauth', methods=['POST'])
def instagram_authorization():
    authorization_url = 'https://api.instagram.com/oauth/authorize/?client_id='\
                        +client_id+'&redirect_uri=http://localhost:5000/instagram/verifyAccount&response_type=code'
    return authorization_url


@app.route('/instagram/verifyAccount', methods=['GET'])
def instagram_account_verify():
    code = request.args.get('code')
    if not code:
        return 'Missing Code'
    try:
        instagram_client = client.InstagramAPI(client_id=client_id,
                                               client_secret=client_secret,
                                               redirect_uri='http://localhost:5000/instagram/verifyAccount')
        access_token, instagram_user = instagram_client.exchange_code_for_access_token(code)

        print instagram_user
        print access_token
    except Exception, e:
        print e
    return render_template('index.html')


@app.route('/linkedIn/Oauth', methods=['POST'])
def linkedin_authorization():
    try:
        global authentication
        authentication = linkedin.LinkedInAuthentication(li_client_id, li_client_secret,
                                                         'http://localhost:5000/linkedIn/verifyAccount',
                                                         linkedin.PERMISSIONS.enums.values())
        print "url"
        print authentication.authorization_url
    except Exception, e:
        print e
    return authentication.authorization_url


@app.route('/linkedIn/verifyAccount', methods=['GET'])
def linkedin_account_verify():
    code = request.args.get('code')
    try:
        authentication.authorization_code = code
        print authentication.get_access_token()
        application = linkedin.LinkedInApplication(authentication)
        print "profile"
        print application.get_profile()
        print "wait"
        print application.make_request('GET', 'http://www.linkedin.com/connected/')
        print application.get_connections()
    except Exception, e:
        print e
    return render_template('index.html')


if __name__ == "__main__":
    app.secret_key = 'mysecret'
    app.run(host='127.0.0.1', port=80)
