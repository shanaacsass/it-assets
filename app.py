from flask import Flask, render_template, request, url_for, session, redirect, flash
import mysql.connector
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
from datetime import datetime

app = Flask(__name__)
# Set a simple secret key for session security (for development only)
app.secret_key = '123'
# Database configuration
app.config["MYSQL_HOST"] = "ap-south.connect.psdb.cloud"
app.config["MYSQL_USER"] = "v40a9v5iob1tyobpgm9o"
app.config["MYSQL_PASSWORD"] = "pscale_pw_wbuubfBvpbhSrk38ogNvaXpWQNnxPvirxmDGeiIm7Yo"
app.config["MYSQL_DB"] = "joviancareers"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

# Specify the path to your CA certificate for SSL
ssl_ca_path = "/etc/ssl/cert.pem"

# Database configuration with SSL
db_config = {
    "host": app.config["MYSQL_HOST"],
    "user": app.config["MYSQL_USER"],
    "password": app.config["MYSQL_PASSWORD"],
    "database": app.config["MYSQL_DB"],
    "ssl_ca": ssl_ca_path,
}

mysql = mysql.connector.connect(**db_config)

bcrypt = Bcrypt(app)

# cipher text package
key = Fernet.generate_key()
cipher_suite = Fernet(key)

def decrypt_data(encrypted_data):
    try:
        decrypted_data = cipher_suite.decrypt(encrypted_data.encode()).decode('utf-8')
        return decrypted_data
    except Exception as e:
        print(f"Error decrypting data: {e}")
        return None

@app.route("/", methods=['GET','POST'])
def index():
    if 'alogin' in request.form:
        if request.method == 'POST':
            # aname = request.form["aname"]
            aemail = request.form["aemail"]
            apass = request.form["apass"]
            try:
                cur = mysql.cursor(dictionary=True)
                cur.execute("select * from admin where aemail=%s and apass=%s", [aemail, apass])
                res = cur.fetchone()
                if res:
                    session["aname"] = res["aname"]
                    session["aid"] = res["aid"]
                    return redirect(url_for('admin_home'))
                else:
                    return render_template("index.html")
            except Exception as e:
                print(e)
            finally:
                cur.close()
                mysql.commit()
                
    elif 'register' in request.form:
        if request.method == 'POST':
            # Inside your registration logic
            encryption_key = Fernet.generate_key()
            fernet = Fernet(encryption_key)
            uname = request.form["uname"]
            password = request.form["upass"]
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')  # Hash the password
            age = request.form["age"]
            address = request.form["address"]
            # Encrypt age and address and uname
            encrypted_uname = fernet.encrypt(uname.encode()).decode('utf-8')
            encrypted_age = fernet.encrypt(age.encode()).decode('utf-8')
            encrypted_address = fernet.encrypt(address.encode()).decode('utf-8')
            mail = request.form["mail"]
            cur = mysql.cursor(dictionary=True)
            cur.execute('INSERT INTO customers (customer_name, customer_password, customer_age, customer_address, customer_email, encryption_key) VALUES (%s, %s, %s, %s, %s, %s)', [encrypted_uname, hashed_password, encrypted_age, encrypted_address, mail, encryption_key])
            mysql.commit()
        return render_template("index.html")

    # customers login based on customers email id and password which was created by admin 
    elif 'ulogin' in request.form:
        if request.method == 'POST':
            Customeremail = request.form["customeremail"]
            Customerpassword = request.form["customerpassword"]
            try:
                cur = mysql.cursor(dictionary=True)
                cur.execute("SELECT * FROM customers WHERE customer_email=%s", [Customeremail])
                res = cur.fetchone()
                if res and bcrypt.check_password_hash(res["customer_password"], Customerpassword):
                    # Load the encryption key from the customers table
                    encryption_key = res["encryption_key"]
                    fernet = Fernet(encryption_key)
                     # Decrypt the customer_name
                    decrypted_customer_name = fernet.decrypt(res["customer_name"].encode()).decode('utf-8')
                    session["customeremail"] = res["customer_email"]
                    session["customername"] = decrypted_customer_name
                    session["Customerid"] = res["customer_id"]
                    return redirect(url_for('user_home'))
                else:
                    return render_template("index.html")
            except Exception as e:
                print(e)
            finally:
                cur.close()
                mysql.commit()

    return render_template("index.html")



# customers fetching on customers login in user_profile.html
@app.route("/user_profile")
def user_profile():
    id = session["Customerid"]  # Get the Customer ID from the session   
    qry = "SELECT * FROM customers WHERE customer_id=%s"  # Query to fetch user data based on the Customer ID  
  # So, when working with mysql.connector in replit, including dictionary=True in the cursor creation is a good practice to ensure that you can access the data using column names in a dictionary format
    cur = mysql.cursor(dictionary=True) # Execute the query with the Customer ID parameter this line and 2nd line
    cur.execute(qry, [id])
    user_data = cur.fetchone() # Fetch the user data as a dictionary  
    cur.close()   # Close the database cursor

    # Check if user data is not found
    if not user_data:
        flash("User Not Found...!!!", "danger") # Display a flash message if user not found
        return render_template("user_profile.html", res=None) # Pass None to the template to handle non-existent user gracefully


    encryption_key = user_data["encryption_key"] # Load the encryption key from the customers table
    fernet = Fernet(encryption_key) # Create a Fernet object with the loaded encryption key

    # Decrypt age and address
    decrypted_name = fernet.decrypt(user_data["customer_name"].encode()).decode('utf-8')
    decrypted_age = fernet.decrypt(user_data["customer_age"].encode()).decode('utf-8') if user_data["customer_age"] else ''  #if user_data["customer_age"] else ''  I add these code because if admin register means this field was empty so if writtenthis code means the empty value also render and display otherwise it show error
    decrypted_address = fernet.decrypt(user_data["customer_address"].encode()).decode('utf-8') if user_data["customer_address"] else '' #if user_data["customer_age"] else ''  I add these code because if admin register means this field was empty so if writtenthis code means the empty value also render and display otherwise it show error

    # Pass the decrypted data and original user data to the user_profile.html template
    return render_template("user_profile.html", user_data=user_data, decrypted_age=decrypted_age, decrypted_address=decrypted_address, decrypted_name=decrypted_name)



# customers login and update
  # customers login and update
@app.route("/update_user", methods=['GET', 'POST'])
def update_user():
  if request.method == 'POST':
      name = request.form['name']
      password = request.form['password']
      age = request.form['age']
      address = request.form['address']
      mail = request.form['mail']
      Customerid = session["Customerid"]

      # Generate a new encryption key
      encryption_key = Fernet.generate_key()
      fernet = Fernet(encryption_key)

      cur = mysql.cursor()

      if password:  # Check if password is provided
          # Hash the password
          hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

          # Encrypt age and address
          encrypted_name = fernet.encrypt(name.encode()).decode('utf-8')
          encrypted_age = fernet.encrypt(age.encode()).decode('utf-8')
          encrypted_address = fernet.encrypt(address.encode()).decode('utf-8')

          cur.execute("UPDATE customers SET customer_name=%s, customer_password=%s, customer_age=%s, customer_address=%s, customer_email=%s, encryption_key=%s WHERE customer_id=%s",
                      [encrypted_name, hashed_password, encrypted_age, encrypted_address, mail, encryption_key, Customerid])
      else:
          # Encrypt age and address
          encrypted_name = fernet.encrypt(name.encode()).decode('utf-8')
          encrypted_age = fernet.encrypt(age.encode()).decode('utf-8')
          encrypted_address = fernet.encrypt(address.encode()).decode('utf-8')

          cur.execute("UPDATE customers SET customer_name=%s, customer_age=%s, customer_address=%s, customer_email=%s, encryption_key=%s WHERE customer_id=%s",
                      [encrypted_name, encrypted_age, encrypted_address, mail, encryption_key, Customerid])

      mysql.commit()
      flash('User Updated Successfully', 'success')
      return redirect(url_for('user_profile'))

  return render_template("user_profile.html")

# admin register for customers email and password and username.. (admin can create customers email, name and password)
@app.route("/admin_home", methods=['GET', 'POST'])
def admin_home():
    adminname = session.get("aname")

    if request.method == 'POST' and 'register' in request.form:
        # Handle user registration
        Customername = request.form["customername"]
        Customeremail = request.form["customeremail"]
        Customerpassword = request.form["customerpassword"]
        encryption_key = Fernet.generate_key()
        fernet = Fernet(encryption_key)
        # Encrypt the customer name
        encrypted_customername = fernet.encrypt(Customername.encode()).decode('utf-8')
        try:
            # Hash the password
            Customerhashedpassword = bcrypt.generate_password_hash(Customerpassword).decode('utf-8')
            # Insert the new user into the admin table
            cur = mysql.cursor()
            cur.execute('INSERT INTO customers (customer_name, customer_email, customer_password, encryption_key) VALUES (%s, %s, %s, %s)', [encrypted_customername, Customeremail, Customerhashedpassword, encryption_key])
            mysql.commit()
            cur.close()

            flash('User registered successfully', 'success')
            return redirect(url_for('admin_home'))

        except Exception as e:
            print(e)
            flash('Error registering user', 'danger')

    return render_template("admin_home.html", aname=adminname)


# Admin view existing customers from customers table
@app.route("/view_users")
def view_users():
    cur = mysql.cursor()  # Initialize a database cursor
    qry = "SELECT * FROM customers"
    cur.execute(qry)
    data = cur.fetchall()  # Fetch all data from the query result
    cur.close()  # Close the database cursor
    count = len(data)  # Count the number of records fetched

    if count == 0:
        flash("Users not found...!!!", "danger")  # Display a flash message if no users are found

    # Decrypt customer names
    decrypted_data = []
    for user_data in data:
        # Decrypt the customer name
        decrypted_name = decrypt_customer_name(user_data['customer_name'], user_data['encryption_key'])  #green colour decrypt_customer_name is function we written function below 
        decrypted_age = decrypt_customer_field(user_data['customer_age'], user_data['encryption_key'])   #green colour decrypt_customer_field is function we written function below
        decrypted_address = decrypt_customer_field(user_data['customer_address'], user_data['encryption_key']) #green colour decrypt_customer_field is function we written function below
        user_data['decrypted_name'] = decrypted_name   # that user_data[decrypted_name] in yellow colour was stored in decrypted_name variable name it is white colour 
        user_data['decrypted_age'] = decrypted_age   
        user_data['decrypted_address'] = decrypted_address
        decrypted_data.append(user_data)

    return render_template("view_users.html", res=decrypted_data)  # Render the template with decrypted user data

# Function to decrypt customer name
def decrypt_customer_name(encrypted_name, encryption_key):
    fernet = Fernet(encryption_key)  # Create a Fernet object with the encryption key
    decrypted_name = fernet.decrypt(encrypted_name.encode()).decode('utf-8')  # Decrypt the customer name
    return decrypted_name

# Function to decrypt customer age and address  //why we written customer_name and customer_age is null means it display empty thats why i written in else condition because the admin register means the customer_address and customer_age field was saved as empty or blank because we dont give a input field for admin 
def decrypt_customer_field(encrypted_field, encryption_key):
    if encrypted_field:  # Check if the field is not empty
        fernet = Fernet(encryption_key)  # Create a Fernet object with the encryption key
        decrypted_field = fernet.decrypt(encrypted_field.encode()).decode('utf-8')  # Decrypt the field
        return decrypted_field
    else:
        return ''  # Return empty string if the field is empty

# admin delete customers data 
@app.route("/delete_users/<string:Customerid>", methods=['GET', 'POST'])
def delete_users(Customerid):
    cur = mysql.connection.cursor()
    cur.execute("delete from customers where customer_id=%s", [Customerid])
    mysql.connection.commit()
    flash("Users Deleted Successfully", "danger")
    return redirect(url_for("view_users"))

# Admin update customers modal code
# Admin update customers modal code
@app.route("/update_user_data/<string:Customerid>", methods=['POST'])
def update_user_data(Customerid):
    print("Updating user data for Customer ID:", Customerid)

    if request.method == 'POST':
        # Fetch data from the form
        update_name = request.form["update_name"]
        update_age = request.form["update_age"]
        update_address = request.form["update_address"]
        update_email = request.form["update_email"]
        update_password = request.form["update_password"]

        try:
            cur = mysql.connection.cursor()

            # Generate a new encryption key
            new_encryption_key = Fernet.generate_key()
            fernet = Fernet(new_encryption_key)

            # Check if the password field is not empty, then update the password
            if update_password:
                # Hash the password
                hashed_password = bcrypt.generate_password_hash(update_password).decode('utf-8')

                # Encrypt age and address
                encrypted_name = fernet.encrypt(update_name.encode()).decode('utf-8')
                encrypted_age = fernet.encrypt(update_age.encode()).decode('utf-8')
                encrypted_address = fernet.encrypt(update_address.encode()).decode('utf-8')

                # Update the customer record with new encrypted information and key
                cur.execute('UPDATE customers SET customer_name=%s, customer_age=%s, customer_address=%s, customer_email=%s, customer_password=%s, encryption_key=%s WHERE customer_id=%s',
                            [encrypted_name, encrypted_age, encrypted_address, update_email, hashed_password, new_encryption_key, Customerid])
            else:
                # Encrypt age and address
                encrypted_name = fernet.encrypt(update_name.encode()).decode('utf-8')
                encrypted_age = fernet.encrypt(update_age.encode()).decode('utf-8')
                encrypted_address = fernet.encrypt(update_address.encode()).decode('utf-8')

                # Update the customer record with new encrypted information and key
                cur.execute('UPDATE customers SET customer_name=%s, customer_age=%s, customer_address=%s, customer_email=%s, encryption_key=%s WHERE customer_id=%s',
                            [encrypted_name, encrypted_age, encrypted_address, update_email, new_encryption_key, Customerid])

            mysql.connection.commit()
            cur.close()

            print('User updated successfully')
            flash('User updated successfully', 'success')
        except Exception as e:
            print(e)
            print('Error updating user')
            flash('Error updating user', 'danger')

    return redirect(url_for('view_users'))



# add asset code
@app.route("/add_asset", methods=['POST'])
def add_asset():
    if request.method == 'POST':
        # Generate a new encryption key for the asset
        encryption_key = Fernet.generate_key()
        fernet = Fernet(encryption_key)

        # Extract asset details from the form
        asset_name = request.form['asset_name']
        asset_description = request.form['asset_description']
        purchase_date = request.form['purchase_date']
        location = request.form['location']

        # Encrypt asset details with the generated key
        encrypted_asset_name = fernet.encrypt(asset_name.encode()).decode('utf-8')
        encrypted_asset_description = fernet.encrypt(asset_description.encode()).decode('utf-8')
        encrypted_purchase_date = fernet.encrypt(purchase_date.encode()).decode('utf-8')
        encrypted_location = fernet.encrypt(location.encode()).decode('utf-8')
        cur = mysql.connection.cursor()

        # Insert the encrypted asset details into the it_assets table
        cur.execute('INSERT INTO it_assets (asset_name, asset_description, purchase_date, location, encryption_key) VALUES (%s, %s, %s, %s, %s)',
                    [encrypted_asset_name, encrypted_asset_description, encrypted_purchase_date, encrypted_location, encryption_key])
        mysql.connection.commit()
        cur.close()

        flash('IT Asset added successfully', 'success')
        return redirect(url_for('admin_home'))

    return render_template("admin_home.html", aname=session.get("aname"))

# fetch assets  this code is view_assets for fetching 
@app.route("/view_assets")
def view_assets():
    # Fetch existing IT assets from the database
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM it_assets")
    existing_assets = cur.fetchall()
    cur.close()

    # Create a list to store decrypted assets
    decrypted_assets = []

    # Iterate through each asset and decrypt the values
    for asset in existing_assets:
        # Retrieve the encryption key for the current asset
        encryption_key = asset['encryption_key']

        # Create a Fernet object using the encryption key
        fernet = Fernet(encryption_key)

        # Decrypt individual columns
        decrypted_asset_name = fernet.decrypt(asset['asset_name'].encode()).decode('utf-8')
        decrypted_asset_description = fernet.decrypt(asset['asset_description'].encode()).decode('utf-8')
        decrypted_purchase_date = fernet.decrypt(asset['purchase_date'].encode()).decode('utf-8')
        decrypted_location = fernet.decrypt(asset['location'].encode()).decode('utf-8')

        # Update the asset dictionary with decrypted values
        asset['asset_name'] = decrypted_asset_name
        asset['asset_description'] = decrypted_asset_description
        asset['purchase_date'] = decrypted_purchase_date
        asset['location'] = decrypted_location

        # Add the updated asset to the list
        decrypted_assets.append(asset)

    # Pass the decrypted assets to the template for rendering
    return render_template("view_assets.html", existing_assets=decrypted_assets)


# Route to delete asset button in view_asset page to delete an IT asset
@app.route("/delete_asset/<int:asset_id>")
def delete_asset(asset_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM it_assets WHERE asset_id = %s", [asset_id])
        mysql.connection.commit()
        cur.close()
        flash('IT Asset deleted successfully', 'success')
    except Exception as e:
        print(e)
        flash('Error deleting IT asset', 'danger')

    return redirect(url_for('view_assets'))

#edit assets for fetching values in edit form in edit_assets.html based on asset_id
@app.route("/edit_asset/<int:asset_id>", methods=['GET', 'POST'])
def edit_asset(asset_id):
    if request.method == 'POST':
        # Fetch data from the form
        update_asset_name = request.form["update_asset_name"]
        update_asset_description = request.form["update_asset_description"]
        update_purchase_date = request.form["update_purchase_date"]
        update_location = request.form["update_location"]

        try:
            cur = mysql.connection.cursor()
            # Generate a new encryption key
            new_encryption_key = Fernet.generate_key()
            fernet = Fernet(new_encryption_key) #Create a Fernet object with the generated encryption key

            # Encrypt the enter text which was enter in input field it was stored in  fetch data from the form that plain text we encrypt and update it into it_assets table
            encrypted_asset_name = fernet.encrypt(update_asset_name.encode()).decode('utf-8')
            encrypted_asset_description = fernet.encrypt(update_asset_description.encode()).decode('utf-8')
            encrypted_purchase_date = fernet.encrypt(update_purchase_date.encode()).decode('utf-8')
            encrypted_location = fernet.encrypt(update_location.encode()).decode('utf-8')

            # Update the IT asset based on the asset ID
            cur.execute('UPDATE it_assets SET asset_name=%s, asset_description=%s, purchase_date=%s, location=%s, encryption_key=%s WHERE asset_id=%s',
                        [encrypted_asset_name, encrypted_asset_description, encrypted_purchase_date, encrypted_location, new_encryption_key, asset_id])

            mysql.connection.commit()
            cur.close()

            flash('IT Asset updated successfully', 'success')
        except Exception as e:
            print(e)
            flash('Error updating IT asset', 'danger')

        return redirect(url_for('view_assets'))

    # Fetch the details of the selected IT asset based on edit_assets.html
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM it_assets WHERE asset_id=%s", [asset_id])
    asset_details = cur.fetchone()
    cur.close()

    # Retrieve the encryption key for the current asset
    encryption_key = asset_details['encryption_key']
    # Create a Fernet object using the encryption key
    fernet = Fernet(encryption_key)

    # Decrypt individual columns
    decrypted_asset_name = fernet.decrypt(asset_details['asset_name'].encode()).decode('utf-8')
    decrypted_asset_description = fernet.decrypt(asset_details['asset_description'].encode()).decode('utf-8')
    decrypted_purchase_date = fernet.decrypt(asset_details['purchase_date'].encode()).decode('utf-8')
    decrypted_location = fernet.decrypt(asset_details['location'].encode()).decode('utf-8')

    # Update the asset details dictionary with decrypted values
    asset_details['asset_name'] = decrypted_asset_name
    asset_details['asset_description'] = decrypted_asset_description
    asset_details['purchase_date'] = decrypted_purchase_date
    asset_details['location'] = decrypted_location

    return render_template("edit_asset.html", asset_details=asset_details)



# Add this route after the admin_home route  this code for inserting code for help disk by customers side to raise query
@app.route("/help_desk", methods=['GET', 'POST'])
def help_desk():
    if request.method == 'POST':
        user_id = session.get("Customerid")  # Assuming you've stored the user ID in the session
        issue_description = request.form["issue_description"]
        priority = request.form["priority"]
        status = "Open" # Set the initial status to "Open"
        timestamp = datetime.now() #The variable timestamp is assigned the current date and time. For example, it might look like this: 2023-11-24 11:31:22.923705

        # Generate a new encryption key
        new_encryption_key = Fernet.generate_key()
        fernet_new = Fernet(new_encryption_key)

        # Encrypt the values with the new encryption key
        encrypt_issue_description = fernet_new.encrypt(issue_description.encode()).decode('utf-8')
        encrypted_priority = fernet_new.encrypt(priority.encode()).decode('utf-8')
        encrypted_status = fernet_new.encrypt(status.encode()).decode('utf-8')
        # Convert timestamp to string before encryption
        str_timestamp = str(timestamp) #The variable str_timestamp is created by converting the timestamp to a string using the str() function. it look like this "2023-11-24 11:31:22.923705"
        encrypted_timestamp = fernet_new.encrypt(str_timestamp.encode()).decode('utf-8')


        try:
            cur = mysql.connection.cursor()
            cur.execute('INSERT INTO help_desk_tickets (user_id, issue_description, status, priority, timestamp, encryption_key) VALUES (%s, %s, %s, %s, %s, %s)',
                        [user_id, encrypt_issue_description, encrypted_status, encrypted_priority, encrypted_timestamp, new_encryption_key])
            mysql.connection.commit()
            cur.close()

            flash('Help desk ticket submitted successfully', 'success')
            return redirect(url_for('user_home'))

        except Exception as e:
            print(e)
            flash('Error submitting help desk ticket', 'danger')

    return render_template("help_desk.html")

# this code is for fetching the All customers help_desk_tickets columns data  in view_help_desk_tickets.html page for admin side admin can see Help desk tickets of all customers
@app.route("/view_help_desk_tickets")
def view_help_desk_tickets():
    try:
        # Fetch all help desk tickets from the database
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM help_desk_tickets")
        help_desk_tickets_data = cur.fetchall()
        cur.close() # Close the cursor as we have fetched the data

        # Create a list to store decrypted help desk tickets
        decrypted_help_desk_tickets = []

        # Loop through each help desk ticket
        for decrypted_ticket_data in help_desk_tickets_data:
            # Extract encryption key from the database
            encryption_key = decrypted_ticket_data['encryption_key']    
            fernet = Fernet(encryption_key) # Create a Fernet object with the encryption key

            # Decrypt ticket details and store in variables
            decrypt_issue_description = fernet.decrypt(decrypted_ticket_data["issue_description"].encode()).decode('utf-8')
            decrypt_status = fernet.decrypt(decrypted_ticket_data["status"].encode()).decode('utf-8')
            decrypt_priority = fernet.decrypt(decrypted_ticket_data["priority"].encode()).decode('utf-8')
            decrypt_timestamp = fernet.decrypt(decrypted_ticket_data["timestamp"].encode()).decode('utf-8')

            # Add the decrypted values to the list as a dictionary
            decrypted_help_desk_tickets.append({
                "ticket_id": decrypted_ticket_data["ticket_id"],
                "user_id": decrypted_ticket_data["user_id"],
                "issue_description": decrypt_issue_description,
                "status": decrypt_status,
                "priority": decrypt_priority,
                "timestamp": decrypt_timestamp
            })

        # Render the template with decrypted help desk tickets
        return render_template("view_help_desk_tickets.html", help_desk_tickets=decrypted_help_desk_tickets)

    except Exception as e:
        # Handle exceptions, print the error, and show a flash message
        print(e)
        flash('Error fetching help desk tickets', 'danger')

    # If there's an error, render the template with an empty list of help desk tickets
    return render_template("view_help_desk_tickets.html", help_desk_tickets=[])



# this code is for when we click update button (button name= is update_ticket) if we click means it will pass with ticket_id to update_ticket.html page
@app.route("/update_ticket/<int:ticket_id>")
def update_ticket(ticket_id):
    # Fetch the ticket details based on the ticket ID
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM help_desk_tickets WHERE ticket_id=%s", [ticket_id])
        ticket_details = cur.fetchone()

        #Load the Existing encryption_key column value form help_desk_tickets table column value
        encryption_key = ticket_details['encryption_key']
        fernet = Fernet(encryption_key)

        # Decrypt ticket details and update the 'ticket_details' dictionary
        decrypt_issue_description = fernet.decrypt(ticket_details["issue_description"].encode()).decode('utf-8')
        decrypt_status = fernet.decrypt(ticket_details["status"].encode()).decode('utf-8')
        decrypt_priority = fernet.decrypt(ticket_details["priority"].encode()).decode('utf-8')
        decrypt_timestamp = fernet.decrypt(ticket_details["timestamp"].encode()).decode('utf-8')

        ticket_details.update({
             "issue_description": decrypt_issue_description,
             "status": decrypt_status,
             "priority": decrypt_priority,
             "timestamp": decrypt_timestamp
        })

        cur.close()

        return render_template("update_ticket.html", ticket_details=ticket_details)
    except Exception as e:
        print(e)
        flash('Error fetching and decrypting ticket details', 'danger')
    return render_template("update_ticket.html", ticket_details=None)

@app.route("/process_update_ticket/<int:ticket_id>", methods=['POST'])
def process_update_ticket(ticket_id):
    if request.method == 'POST':
        new_status = request.form['status']
        new_user_id = request.form['user_id']
        new_issue_description = request.form['issue_description']
        new_priority = request.form['priority']
        new_timestamp = datetime.now()

        # Generate a new encryption key
        new_encryption_key = Fernet.generate_key() # Generate a new encryption key
        fernet = Fernet(new_encryption_key) 

        # Encrypt all the relevant fields
        encrypted_new_status = fernet.encrypt(new_status.encode()).decode('utf-8')
        encrypted_issue_description = fernet.encrypt(new_issue_description.encode()).decode('utf-8')
        encrypted_new_priority = fernet.encrypt(new_priority.encode()).decode('utf-8')

        # Convert timestamp to string before encryption
        str_timestamp = str(new_timestamp)
        encrypted_timestamp = fernet.encrypt(str_timestamp.encode()).decode('utf-8')

        try:
            cur = mysql.connection.cursor()
            cur.execute('UPDATE help_desk_tickets SET status=%s, user_id=%s, issue_description=%s, priority=%s, timestamp=%s, encryption_key=%s WHERE ticket_id=%s',
                        [encrypted_new_status, new_user_id, encrypted_issue_description, encrypted_new_priority, encrypted_timestamp, new_encryption_key, ticket_id])
            mysql.connection.commit()
            cur.close()

            flash('Help desk ticket updated successfully', 'success')
        except Exception as e:
            print(e)
            flash('Error updating help desk ticket', 'danger')

        return redirect(url_for('view_help_desk_tickets'))


#  based on session["CustomerId"] it fetch the status in view_user_tickets.html from help_desk_tickets column based on user_id
@app.route("/view_user_tickets")
def view_user_tickets():
    try:
        # Get the user ID from the session
        user_id = session["Customerid"]
        # Fetch user's help desk tickets from the database
        cur = mysql.connection.cursor()
        cur.execute('SELECT * FROM help_desk_tickets WHERE user_id=%s', [user_id])
        user_tickets = cur.fetchall()

        # Decrypt ticket details using the encryption key
        decrypted_user_tickets = []
        for decrypted_user_help_tickets in user_tickets:
            encryption_key = decrypted_user_help_tickets['encryption_key']  # Extract encryption key from the help_desk_tickets table column of encryption_key
            fernet = Fernet(encryption_key) # Create a Fernet object with the encryption key

            # Decrypt ticket details and store in variables
            decrypt_issue_description = fernet.decrypt(decrypted_user_help_tickets["issue_description"].encode()).decode('utf-8')
            decrypt_status = fernet.decrypt(decrypted_user_help_tickets["status"].encode()).decode('utf-8')
            decrypt_priority = fernet.decrypt(decrypted_user_help_tickets["priority"].encode()).decode('utf-8')
            decrypt_timestamp = fernet.decrypt(decrypted_user_help_tickets["timestamp"].encode()).decode('utf-8')

            # Add the decrypted values to the list as a dictionary
            decrypted_user_tickets.append({
                "ticket_id": decrypted_user_help_tickets["ticket_id"],
                "user_id": decrypted_user_help_tickets["user_id"],
                "issue_description": decrypt_issue_description,
                "status": decrypt_status,
                "priority": decrypt_priority,
                "timestamp": decrypt_timestamp
            })

        cur.close()
        # Render the template with decrypted user tickets
        return render_template("view_user_tickets.html", user_tickets=decrypted_user_tickets)

    except Exception as e:
        print(e)
        flash('Error fetching user tickets', 'danger')
        return render_template("user_home.html", user_tickets=None)   # Redirect to a suitable page if there's an error

# Fetch IT asset data
# Insert assignment details into assigned_assets_customers table for each selected asset
@app.route("/assign_assets", methods=['GET', 'POST'])
def assign_assets():
    if request.method == 'POST':
        if 'assign' in request.form:
            customer_id = request.form["customer_id"]
            asset_ids = request.form.getlist("asset_id[]")

            # Fetch customer details and encryption_key based on customer_id
            cur = mysql.connection.cursor()
            cur.execute("SELECT customer_name, customer_address, customer_email, encryption_key FROM customers WHERE customer_id=%s", [customer_id])
            customer_details = cur.fetchone()

            if customer_details:
                try:
                    # Create Fernet objects with the existing encryption keys for customer
                    encryption_key_customer = customer_details['encryption_key']  # Load the existing encryption key from the customers table
                    fernet_customer = Fernet(encryption_key_customer)  # Create a Fernet object based on the loaded encryption key

                    # Use a common encryption key for all assets assigned to the customer
                    new_encryption_key_asset = Fernet.generate_key()  # Generate a new encryption key
                    fernet_assigned_asset = Fernet(new_encryption_key_asset)  # Store the generated encryption key in a Fernet object

                    # Decrypt and encrypt customer_name
                    decrypted_customer_name = fernet_customer.decrypt(customer_details["customer_name"].encode()).decode('utf-8')  # Decrypt customer_name
                    encrypted_customer_name = fernet_assigned_asset.encrypt(decrypted_customer_name.encode()).decode('utf-8')  # Encrypt customer_name for inserting into the customer_name column in the assigned_assets_customer table

                    # Encrypt customer_email with the common encryption key
                    encrypted_customer_email = fernet_assigned_asset.encrypt(customer_details["customer_email"].encode()).decode('utf-8')

                    # Handle customer_address
                    if customer_details["customer_address"]:  # Check if customer_address is not empty
                        # Decrypt and encrypt customer_address
                        decrypted_customer_address = fernet_customer.decrypt(customer_details["customer_address"].encode()).decode('utf-8')
                        encrypted_customer_address = fernet_assigned_asset.encrypt(decrypted_customer_address.encode()).decode('utf-8')
                    else:
                        # If customer_address is empty, insert as empty
                        encrypted_customer_address = ""

                    # Insert assignment details into assigned_assets_customers table for each selected asset
                    for asset_id in asset_ids:
                        # Fetch asset details and encryption_key based on asset_id
                        cur.execute("SELECT asset_name, asset_description, encryption_key FROM it_assets WHERE asset_id=%s", [asset_id])
                        asset_details = cur.fetchone()

                        if asset_details:
                            # Create Fernet object with the existing encryption key for the asset
                            encryption_key_asset = asset_details['encryption_key']
                            fernet_asset = Fernet(encryption_key_asset)

                            # Decrypt asset details
                            decrypted_asset_name = fernet_asset.decrypt(asset_details["asset_name"].encode()).decode('utf-8')
                            decrypted_asset_description = fernet_asset.decrypt(asset_details["asset_description"].encode()).decode('utf-8')

                            # Encrypt asset details with the common encryption key stored in the fernet_assigned_asset object
                            encrypted_asset_name = fernet_assigned_asset.encrypt(decrypted_asset_name.encode()).decode('utf-8')
                            encrypted_asset_description = fernet_assigned_asset.encrypt(decrypted_asset_description.encode()).decode('utf-8')

                            # Insert into assigned_assets_customers table
                            cur.execute('INSERT INTO assigned_assets_customers (customer_id, asset_id, assignment_date, customer_name, customer_email, customer_address, asset_name, asset_description, encryption_key) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)',
                                        [customer_id, asset_id, datetime.now(), encrypted_customer_name, encrypted_customer_email, encrypted_customer_address, encrypted_asset_name, encrypted_asset_description, new_encryption_key_asset])

                    mysql.connection.commit()
                    cur.close()

                    flash('Assets assigned successfully', 'success')
                    return redirect(url_for('view_assigned_assets'))  # Redirect to the view_assigned_assets page
                except Exception as e:
                    print(e)
                    # Print the traceback for more detailed error information
                    import traceback
                    traceback.print_exc()

                    flash('Error assigning assets', 'danger')



    # Fetch existing customer_ids and asset_ids on assign_assets.html page
    cur = mysql.connection.cursor()
    # Fetch customer data with encrypted customer names
    cur.execute("SELECT customer_id, customer_name, encryption_key FROM customers")
    customer_data = cur.fetchall()
    # Decrypt customer names
    decrypted_customer_data = []
    for customer in customer_data:
        encryption_key = customer['encryption_key'] # Retrieve & Load the encryption key from the customers table
        fernet = Fernet(encryption_key) # Create a Fernet object with the loaded encryption key
        decrypted_customer_name = fernet.decrypt(customer['customer_name'].encode()).decode('utf-8') # decrypt the customer_name column value and store that in customer[customer_name] variable
        customer['customer_name'] = decrypted_customer_name
        decrypted_customer_data.append(customer)

    # Fetch IT asset data with encrypted asset names with asset_id in assign_assets.html page
    cur.execute("SELECT asset_id, asset_name, encryption_key FROM it_assets")
    asset_data = cur.fetchall()
    # Decrypt asset names in assign_asset.html page
    decrypted_asset_data = []
    for asset in asset_data:
        encryption_key = asset['encryption_key'] #Retrieve & Load the encryption key from the it_assets table
        fernet = Fernet(encryption_key)  # Create a Fernet object with the loaded encryption key
        decrypted_asset_name = fernet.decrypt(asset['asset_name'].encode()).decode('utf-8') # decrypt the asset_name column value and store that in asset[asset_name] variable
        asset ['asset_name'] = decrypted_asset_name
        decrypted_asset_data.append(asset)
    cur.close()
    # Pass the decrypted customer data and IT asset data to the template
    return render_template("assign_assets.html", customer_data=decrypted_customer_data, asset_data=decrypted_asset_data)


# Admin view assigned assets in decrypted form in view_assigned_assets.html page
@app.route("/view_assigned_assets")
def view_assigned_assets():
    try:
        # Fetch data from the assigned_assets_customers table
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM assigned_assets_customers")
        assigned_assets_data = cur.fetchall()

        # Decrypt encrypted values using the common encryption key
        decrypted_assets_data = []
        for asset_data in assigned_assets_data:
            # Load the existing encryption key from the assigned_assets_customers table
            encryption_key_customer = asset_data['encryption_key']
            fernet_encryption_key = Fernet(encryption_key_customer) # Create a Fernet object with the existing encryption key

            # Decrypt customer_name
            decrypted_customer_name = fernet_encryption_key.decrypt(asset_data['customer_name'].encode()).decode('utf-8')

            # Decrypt customer_email (assuming it's not encrypted, as mentioned earlier)
            decrypted_customer_email = fernet_encryption_key.decrypt(asset_data['customer_email'].encode()).decode('utf-8')

            # Decrypt customer_address
            if asset_data['customer_address']:
                decrypted_customer_address = fernet_encryption_key.decrypt(asset_data['customer_address'].encode()).decode('utf-8')
            else:
                decrypted_customer_address = ''

            # Decrypt asset_name and asset_description
            decrypted_asset_name = fernet_encryption_key.decrypt(asset_data['asset_name'].encode()).decode('utf-8')
            decrypted_asset_description = fernet_encryption_key.decrypt(asset_data['asset_description'].encode()).decode('utf-8')

            # Create a new dictionary with decrypted values
            decrypted_data_entry = {
                'assignment_id': asset_data['assignment_id'],
                'customer_id': asset_data['customer_id'],
                'asset_id': asset_data['asset_id'],
                'asset_name': decrypted_asset_name,
                'asset_description': decrypted_asset_description,
                'assignment_date': asset_data['assignment_date'],
                'customer_name': decrypted_customer_name,
                'customer_email': decrypted_customer_email,
                'customer_address': decrypted_customer_address,
            }

            decrypted_assets_data.append(decrypted_data_entry)

        cur.close()

        return render_template("view_assigned_assets.html", assigned_assets_data=decrypted_assets_data)

    except Exception as e:
        print(e)
        # Print the traceback for more detailed error information
        import traceback
        traceback.print_exc()

        flash(f'Error fetching assigned assets data: {str(e)}', 'danger')

    return render_template("view_assigned_assets.html", assigned_assets_data=[])




# Edit assigned asset and update when we click the update button means it will update page was edit_
@app.route("/edit_assigned_asset/<int:assignment_id>", methods=['GET', 'POST'])
def edit_assigned_asset(assignment_id):
    if request.method == 'POST':
        if 'update' in request.form:
            try:
                # Extract form data
                customer_id = request.form["customer_id"]
                asset_id = request.form["asset_id"]
                asset_name = request.form["asset_name"]
                asset_description = request.form["asset_description"]

                customer_name = request.form["customer_name"]
                customer_email = request.form["customer_email"]
                customer_address = request.form["customer_address"]
                # Add additional fields as needed
                # ...

                # Generate a new encryption key based on the values entered by the user

                new_encryption_key = Fernet.generate_key()
                fernet_new = Fernet(new_encryption_key)

                # Encrypt the values with the new encryption key
                encrypted_asset_name = fernet_new.encrypt(asset_name.encode()).decode('utf-8')
                encrypted_asset_description = fernet_new.encrypt(asset_description.encode()).decode('utf-8')
                encrypted_customer_name = fernet_new.encrypt(customer_name.encode()).decode('utf-8')
                encrypted_customer_email = fernet_new.encrypt(customer_email.encode()).decode('utf-8')
                # Check if customer_address is not empty
                if customer_address:
                    encrypted_customer_address = fernet_new.encrypt(customer_address.encode()).decode('utf-8')
                else:
                    encrypted_customer_address = ''  # Set to empty string for blank values

                # Update the assigned_assets_customers table with the new values and new encryption key
                cur = mysql.connection.cursor()
                cur.execute('UPDATE assigned_assets_customers SET customer_id=%s, asset_id=%s, asset_name=%s, asset_description=%s, customer_name=%s, customer_email=%s, customer_address=%s, assignment_date=%s, encryption_key=%s WHERE assignment_id=%s',
                            [customer_id, asset_id, encrypted_asset_name, encrypted_asset_description, encrypted_customer_name, encrypted_customer_email, encrypted_customer_address, datetime.now(), new_encryption_key, assignment_id])
                mysql.connection.commit()
                cur.close()

                flash('Asset updated successfully', 'success')
                return redirect(url_for('view_assigned_assets'))

            except Exception as e:
                print(e)
                flash('Error updating asset', 'danger')

    try:
        # Fetch existing data for the specified assignment_id
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM assigned_assets_customers WHERE assignment_id=%s", [assignment_id])
        assigned_asset_data = cur.fetchone()

        # Decrypt asset details using the encryption key
        encryption_key = assigned_asset_data['encryption_key']
        fernet = Fernet(encryption_key)

        # Decrypt asset details and store in variables
        decrypted_asset_name = fernet.decrypt(assigned_asset_data["asset_name"].encode()).decode('utf-8')
        decrypted_asset_description = fernet.decrypt(assigned_asset_data["asset_description"].encode()).decode('utf-8')

        # Decrypt customer_address if it's not empty
        if assigned_asset_data['customer_address']:
            decrypted_customer_address = fernet.decrypt(assigned_asset_data['customer_address'].encode()).decode('utf-8')
        else:
            decrypted_customer_address = ''

        # Decrypt customer_name
        decrypted_customer_name = fernet.decrypt(assigned_asset_data["customer_name"].encode()).decode('utf-8')
        # Decrypt customer_email
        decrypted_customer_email = fernet.decrypt(assigned_asset_data["customer_email"].encode()).decode('utf-8')
        cur.close()

        # Render the template with the assigned asset data and decrypted values
        #1. Left side (orange colour text): Decrypted_asset_name is the variable in the template we just paste this variable in template html code.
        #2. Right side (white colour text): decrypted_asset_name is the actual variable or value that will be inserted into the value attribute of the input field in the template.
        return render_template("edit_assigned_asset.html", assigned_asset_data=assigned_asset_data,
                               Decrypted_asset_name=decrypted_asset_name, Decrypted_asset_description=decrypted_asset_description, Decrypted_customer_address=decrypted_customer_address, Decrypted_customer_name=decrypted_customer_name, Decrypted_customer_email=decrypted_customer_email) 

    except Exception as e:
        print(e)
        flash('Error fetching assigned asset data', 'danger')

    # Render the template with None values in case of an error
    return render_template("edit_assigned_asset.html", assigned_asset_data=None,
                           Decrypted_asset_name=None, Decrypted_asset_description=None,  Decrypted_customer_address=None, Decrypted_customer_name=None, Decrypted_customer_email=None)

# Delete assigned asset in view_assigned_assets.html page itself
@app.route("/delete_assigned_asset/<int:assignment_id>", methods=['POST'])
def delete_assigned_asset(assignment_id):
    try:
        # Delete the assigned asset from the assigned_assets_customers table
        cur = mysql.connection.cursor()
        cur.execute('DELETE FROM assigned_assets_customers WHERE assignment_id=%s', [assignment_id])
        mysql.connection.commit()
        cur.close()

        flash('Asset deleted successfully', 'success')
    except Exception as e:
        print(e)
        flash('Error deleting asset', 'danger')

    return redirect(url_for('view_assigned_assets'))

# Add this route after the user_home route Fetch data from the assigned_assets_customers table based on the customer_id
@app.route("/view_assigned_assets_customer")
def view_assigned_assets_customer():
    try:
        # Fetch data from the assigned_assets_customers table based on the customer_id
        customer_id = session.get("Customerid")
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM assigned_assets_customers WHERE customer_id=%s", [customer_id])
        assigned_assets_data_customer = cur.fetchall()

        # Decrypt asset details using the encryption key
        decrypted_assets_data = [] #Iterate over the fetched data, decrypt the asset name and description for each entry, and store the decrypted values in a list (decrypted_assets_data).
        for assigned_asset_customer in assigned_assets_data_customer:
            encryption_key = assigned_asset_customer['encryption_key'] #load the encryption_key column value
            fernet = Fernet(encryption_key) # Create a Fernet object with the existing encryption key

            # Decrypt asset details and store in variables
            decrypted_asset_name = fernet.decrypt(assigned_asset_customer["asset_name"].encode()).decode('utf-8')
            decrypted_asset_description = fernet.decrypt(assigned_asset_customer["asset_description"].encode()).decode('utf-8')

            # Add the decrypted values to the list
            decrypted_assets_data.append({
                "assignment_id": assigned_asset_customer["assignment_id"],
                "asset_id": assigned_asset_customer["asset_id"],
                "asset_name": decrypted_asset_name,
                "asset_description": decrypted_asset_description,
                "assignment_date": assigned_asset_customer["assignment_date"]
                # Add additional columns as needed
            })

        cur.close()

        return render_template("view_assigned_assets_customer.html", assigned_assets_data_customer=decrypted_assets_data)

    except Exception as e:
        print(e)
        flash('Error fetching assigned assets data', 'danger')

    # Render the template with None values in case of an error
    return render_template("view_assigned_assets_customer.html", assigned_assets_data_customer=None)



@app.route("/user_home")
def user_home():
    return render_template("user_home.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
  app.run(host='0.0.0.0', debug=True)
