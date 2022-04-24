from flask import Flask , request , jsonify,make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import or_ 
import datetime
from werkzeug.security import generate_password_hash,check_password_hash
import jwt
from functools import wraps
from flask_marshmallow import Marshmallow

EXPIRATION = 30
app = Flask(__name__)

app.config['SECRET_KEY']= 'secret'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'


db = SQLAlchemy(app)
ma = Marshmallow(app)

#Define our sql classes
class User(db.Model):
    id = db.Column(db.Integer , primary_key = True)   
    username = db.Column(db.String(50) , unique = True)
    password = db.Column(db.String(80))


class Message(db.Model):
    id = db.Column(db.Integer , primary_key = True)
    body = db.Column(db.String(150) ,nullable=False)
    read = db.Column(db.Boolean() , default = False)
    sender = db.Column(db.String(80), nullable = False)
    recipient = db.Column(db.String(80) , nullable = False)
    subject = db.Column(db.String(30), nullable=False)
    creation_date = db.Column(db.DateTime , default = datetime.datetime.now())


#Define schemas
class MessageSchema(ma.Schema):
    class Meta:
        fields = ('id','body','read','sender','recipient','subject','creation_date')

message_schema = MessageSchema()
messages_schema = MessageSchema(many = True)


def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token = None
        
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        #if token is not found
        if not token:
            return {"message":"Token is missing."} , 401


        try:
            data = jwt.decode(token , app.config['SECRET_KEY'],algorithms=["HS256"])
            current_user = User.query.filter_by(id = data['user_id']).first()
        except:
            return {"message":"Token is invalid."} , 401

        return f(current_user , *args,**kwargs)
    return decorated

#register a user
@app.route("/user" , methods = ['POST'])
def create_user():
    
    data = request.get_json(force=True)
    
    hashed_pass = generate_password_hash(data['password'] , method='sha256')
    username = data['username']
    users = User.query.filter_by(username = username).first()
    if users is not None:
        return "Username already exists."

    user = User(username =username , password = hashed_pass)

    db.session.add(user)
    db.session.commit()
    return jsonify({"message":"new user created"})


@app.route("/login")
def login():
    auth = request.authorization
    
    if not auth or not auth.username or not auth.password:
        return make_response("Could not verify",401,{'WWW-Authenticate':'Basic realm:"Login required"'})

    user = User.query.filter_by(username = auth.username).first()
    if not user:
        return make_response("Could not verify",401,{'WWW-Authenticate':'Basic realm:"Login required"'})

    if check_password_hash(user.password , auth.password):
        token = jwt.encode({'user_id':user.id, 'exp':datetime.datetime.utcnow() + datetime.timedelta(EXPIRATION)} , app.config['SECRET_KEY'])
    
        return ({'token':token})
    
    return make_response("Could not verify",401,{'WWW-Authenticate':'Basic realm:"Login required"'})


#create a message
@app.route("/message" , methods = ['POST'])
@token_required
def create_msg(current_user):

    info = request.get_json(force=True)    
    reciever_username = info['recipient']
    user = User.query.filter_by(username = reciever_username).first()

    if not user:
        return "User with id {} does not exists.".format(reciever_username) , 404

    msg = Message (body = info['body'] , sender = current_user.username , recipient = reciever_username , subject = info['subject'])
    db.session.add(msg)
    db.session.commit()

    return jsonify({"message":"Message was created successfully."}),200

#get all msgs for a user
@app.route("/message/get_all",methods = ['GET'])
@token_required
def get_all_msgs(current_user):

    username = current_user.username
    messages = Message.query.filter_by(recipient = username).all()
    if not messages:
        return {"message":"There are no messages for user "+username} , 401


    return jsonify(messages_schema.dump(messages))


#get all unread msgs for a user
@app.route("/message/get_unread",methods = ['GET'])
@token_required
def get_unread_msgs(current_user):

    username = current_user.username
    messages = Message.query.filter(Message.recipient == username,Message.read == 0).all()
    if not messages:
        return {"message":"There are no unread messages for user "+username},404


    return jsonify(messages_schema.dump(messages))


#read one message
@app.route("/message/<msg_id>" , methods = ['GET'])
@token_required
def get_one_msg(current_user , msg_id):

    message = Message.query.filter(Message.recipient == current_user.username , Message.id == msg_id).first()
    if not message:
        return {"message":"Couldn't find message with id {}".format(msg_id)},404

    #update the unread status of the message
    message.read = True
    db.session.commit()

    return jsonify(message_schema.dump(message))

#Delete message (as owner or as receiver)
@app.route("/message/<msg_id>" , methods = ['DELETE'])
@token_required
def delete_one_msg(current_user , msg_id):
    
    username = current_user.username
    message = Message.query.filter(or_(Message.recipient == username,Message.sender == username),
                                    Message.id == msg_id).first()

    if not message:
        return {"message":"Couldn't find message with id {} .".format(msg_id)} , 404

    db.session.delete(message)
    db.session.commit()

    return {"message":"Message with id {} has been deleted.".format(msg_id)}

if __name__ == '__main__':
    app.run()
    