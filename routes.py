from datetime import timezone
from urllib.parse import urlsplit
import sqlalchemy as sa
from flask import jsonify
from flask import render_template, flash, redirect, url_for, request
from flask_login import login_user, logout_user, current_user, login_required
from app.email import send_password_reset_email
from app.forms import LoginForm, RegistrationForm, EditProfileForm, \
    EmptyForm, PostForm, ResetPasswordRequestForm, ResetPasswordForm, TransactionForm
from app import app, db
from app.models import User, Post
#from app.blockchain import *
from app.blockie import *
from app.blockchain import blockchainObj, logger
from flask_login import current_user
from uuid import uuid4
import json
from datetime import datetime

node_identifier = str(uuid4()).replace('-', '')

##############################################################################################################
#BASE------>
@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.now(timezone.utc)
        db.session.commit()


@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(body=form.post.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post is now live!')
        return redirect(url_for('index'))
    page = request.args.get('page', 1, type=int)
    posts = db.paginate(current_user.following_posts(), page=page,
                        per_page=app.config['POSTS_PER_PAGE'], error_out=False)
    next_url = url_for('index', page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('index', page=posts.prev_num) \
        if posts.has_prev else None
    return render_template('index.html', title='Home', form=form,
                           posts=posts.items, next_url=next_url,
                           prev_url=prev_url)


@app.route('/explore')
@login_required
def explore():
    page = request.args.get('page', 1, type=int)
    query = sa.select(Post).order_by(Post.timestamp.desc())
    posts = db.paginate(query, page=page,
                        per_page=app.config['POSTS_PER_PAGE'], error_out=False)
    next_url = url_for('explore', page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('explore', page=posts.prev_num) \
        if posts.has_prev else None
    return render_template('index.html', title='Explore', posts=posts.items,
                           next_url=next_url, prev_url=prev_url)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.scalar(
            sa.select(User).where(User.username == form.username.data))
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or urlsplit(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        keyGen = blockchainObj.generateKeys(form.username.data)  # Pass the username here
        user = User(username=form.username.data, email=form.email.data, key=keyGen)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        login()
        return redirect(url_for('index'))
    return render_template('register.html', title='Register', form=form)



@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = db.session.scalar(
            sa.select(User).where(User.email == form.email.data))
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html',
                           title='Reset Password', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)


@app.route('/user/<username>')
@login_required
def user(username):
    user = db.first_or_404(sa.select(User).where(User.username == username))
    page = request.args.get('page', 1, type=int)
    query = user.posts.select().order_by(Post.timestamp.desc())
    posts = db.paginate(query, page=page,
                        per_page=app.config['POSTS_PER_PAGE'],
                        error_out=False)
    next_url = url_for('user', username=user.username, page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('user', username=user.username, page=posts.prev_num) \
        if posts.has_prev else None
    form = EmptyForm()
    return render_template('user.html', user=user, posts=posts.items,
                           next_url=next_url, prev_url=prev_url, form=form)


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title='Edit Profile',
                           form=form)


@app.route('/follow/<username>', methods=['POST'])
@login_required
def follow(username):
    form = EmptyForm()
    if form.validate_on_submit():
        user = db.session.scalar(
            sa.select(User).where(User.username == username))
        if user is None:
            flash(f'User {username} not found.')
            return redirect(url_for('index'))
        if user == current_user:
            flash('You cannot follow yourself!')
            return redirect(url_for('user', username=username))
        current_user.follow(user)
        db.session.commit()
        flash(f'You are following {username}!')
        return redirect(url_for('user', username=username))
    else:
        return redirect(url_for('index'))


@app.route('/unfollow/<username>', methods=['POST'])
@login_required
def unfollow(username):
    form = EmptyForm()
    if form.validate_on_submit():
        user = db.session.scalar(
            sa.select(User).where(User.username == username))
        if user is None:
            flash(f'User {username} not found.')
            return redirect(url_for('index'))
        if user == current_user:
            flash('You cannot unfollow yourself!')
            return redirect(url_for('user', username=username))
        current_user.unfollow(user)
        db.session.commit()
        flash(f'You are not following {username}.')
        return redirect(url_for('user', username=username))
    else:
        return redirect(url_for('index'))
#########################################################################################################
#########################################################################################################
#########################################################################################################
#Blockie---------->
@app.route('/Blockie', methods=['GET', 'POST'])
@login_required
def Blockie():
    if request.method == 'POST':
        if "submit_button1" in request.form and request.form["submit_button1"] == 'Block explorer':
            return redirect(url_for('display_chain'))
        elif 'submit_button2' in request.form and request.form['submit_button2'] == 'Mine block':
            return redirect(url_for('mining'))
        elif 'submit_button3' in request.form and request.form['submit_button3'] == 'Check integrity':
            return redirect(url_for('valid'))
        elif 'submit_button4' in request.form and request.form['submit_button4'] == 'Leaderboard':
            return redirect(url_for('leaderboard'))

    return render_template('Blockie.html')



# Mining a new block

@app.route('/mine_block', methods=['POST'])
def mine_block():
    data = request.get_json()
    proof = data.get('proof')
    speed = round(data.get('speed'),2)
    username0 = str(current_user)
    username = username0[6:-1]
    difficulty = data.get('difficulty')
    previous_hash = blockie.hash(blockie.get_previous_block())

    block = blockie.create_block(proof, previous_hash)

    response = {
        'message': f"Block mined in {speed:.4f} seconds, by {username}",
        'index': block['index'],
        'timestamp': block['timestamp'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash']
    }
    with open('scores.json', 'r') as file:
        leaderboard = json.load(file)
    score_data = {'username': username, 'difficulty': difficulty, 'speed': speed}
    leaderboard.append(score_data)

    with open('scores.json', 'w') as file:
        json.dump(leaderboard, file, indent=4)
    return jsonify(response), 200

@app.route('/mining', methods=['GET'])
def mining():
    return render_template('mine.html')

@app.route('/get_previous_proof', methods=['GET'])
def get_previous_proof():
    previous_block = blockie.get_previous_block()
    response = {'previous_proof': previous_block['proof']}
    return jsonify(response), 200




@app.route('/get_chain', methods=['GET'])
def display_chain():
    with open('chain_data.json', 'r') as file:
        data = json.load(file)
    return render_template('get_chain.html', data=data)

# Check validity of blockchain


@app.route('/valid', methods=['GET', 'POST'])
def valid():
    with open('chain_data.json', 'r') as file:
        blockie.chain = json.load(file)
    valid = blockie.chain_valid(blockie.chain)

    if valid:
        response = 'Woohoo, Blockie is doing just fine! Thanks for checking in.'
        image = 'https://thumbs.dreamstime.com/b/cute-smiling-robot-bot-show-muscle-vector-modern-flat-cartoon-character-illustration-isolated-white-background-friendly-strong-157203134.jpg'
    else:
        response = 'Oh noo, Blockie is fecked! Not another fork? :('
        image = 'https://cdn.vectorstock.com/i/preview-1x/53/06/cute-sad-angry-robot-bot-vector-27845306.jpg'
    return render_template('valid.html', response=response, robot_image=image)


@app.route('/leaderboard')
def leaderboard():
    # Load data from JSON file
    with open('scores.json') as f:
        data = json.load(f)

    # Get the difficulty filter from the query parameters
    difficulty = request.args.get('difficulty', 'all')

    # Filter data based on difficulty
    if difficulty != 'all':
        data = [entry for entry in data if entry['difficulty'] == difficulty]

    lowest_easy = min((entry['speed'] for entry in data if entry['difficulty'] == 'easy'), default=None)
    lowest_medium = min((entry['speed'] for entry in data if entry['difficulty'] == 'medium'), default=None)
    lowest_hard = min((entry['speed'] for entry in data if entry['difficulty'] == 'hard'), default=None)
    lowest_extreme = min((entry['speed'] for entry in data if entry['difficulty'] == 'extreme'), default=None)

    return render_template('leaderboard.html', data=data, lowest_easy=lowest_easy, lowest_medium=lowest_medium,
                           lowest_hard=lowest_hard, lowest_extreme=lowest_extreme)


#########################################################################################################
#########################################################################################################
#########################################################################################################
#BLOCKCHAIN------->
@app.route("/blockchain")
@login_required
def blockchain():
    # Handle blockchain requests and resolve conflicts
    blockchainObj.resolve_conflicts()
    logger.info("Accessed blockchain endpoint.")
    return render_template('blockchain.html', title="Blockchain", blockchain=blockchainObj)


@app.route("/transaction", methods=['GET', 'POST'])
def transaction():
    form = TransactionForm()

    if form.validate_on_submit():
        # Load keys for the sender
        sender_private_key_string, sender_public_key_string = blockchainObj.load_keys(form.sender.data)

        logger.info("Sender keys loaded for transaction.")

        # Load keys for the receiver
        receiver_private_key_string, receiver_public_key_string = blockchainObj.load_keys(form.receiver.data)

        logger.info("Receiver keys loaded for transaction.")

        # Call addTransaction with the sender's private key
        feedback = blockchainObj.add_transaction(
            form.sender.data,
            form.receiver.data,
            form.amount.data,
            sender_private_key_string
        )

        if feedback:
            flash('Transaction Made!', 'success')
        else:
            flash('Error!', 'danger')

        return render_template('transaction.html', title="Transaction", blockchain=blockchainObj, form=form)

    return render_template('transaction.html', title="Transaction", blockchain=blockchainObj, form=form)


@app.route("/minerPage")
@login_required
def minerPage():
    logger.info("Accessed miner page.")
    return render_template('minerPage.html', title="Mine", blockchain=blockchainObj, transaction=transaction())


@app.route("/node")
@login_required
def node():
    logger.info("Accessed node page.")
    return render_template('node.html', title="Node")


@app.route("/account")
@login_required
def account():
    logger.info("Accessed account page.")
    return render_template('account.html', title='Account', blockchain=blockchainObj)


# BLOCKCHAIN BACKEND REQUESTS
@app.route('/mine', methods=['GET'])
@login_required
def mine():
    logger.info("Mining request received.")
    miner = request.args.get('miner', None)
    lastBlock = blockchainObj.get_last_block()


    feedback = blockchainObj.mine_pending_transactions(miner)
    if feedback:
        flash(f'Block Mined! Your mining reward has now been added to the pending transactions!', 'success')
    else:
        flash(f'Error!', 'danger')
    return render_template('minerPage.html', title="Mine", blockchain=blockchainObj)


@app.route('/transactions/new', methods=['POST'])
@login_required
def new_transaction():
    values = request.get_json()
    required = ['sender', 'receiver', 'amt']
    if not all(k in values for k in required):
        logger.warning("Missing values in transaction request.")
        return 'Missing values', 400

    index = blockchainObj.add_transaction(values['sender'], values['receiver'], values['amt'])
    response = {'message': f'Transaction will be added to Block {index}'}
    logger.info("New transaction added: %s", response)
    return jsonify(response), 201


@app.route('/chain', methods=['GET'])
@login_required
def full_chain():
    response = {
        'chain': blockchainObj.chainJSONencode(),
        'length': len(blockchainObj.chain),
    }
    logger.info("Chain requested.")
    return jsonify(response), 200


# Blockchain decentralized nodes
@app.route('/nodes/register', methods=['POST'])
@login_required
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        logger.warning("Error: Missing nodes in registration request.")
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchainObj.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchainObj.nodes),
    }
    logger.info("Nodes registered: %s", response)
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
@login_required
def consensus():
    replaced = blockchainObj.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchainObj.chainJSONencode()
        }
        logger.info("Chain was replaced with a new chain.")
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchainObj.chainJSONencode()
        }
        logger.info("Current chain remains authoritative.")

    return jsonify(response), 200

@app.route('/coin_metrics', methods=['GET'])
@login_required
def coin_metrics():
    # Gather coin metrics from the blockchain
    total_supply = blockchainObj.fixed_supply
    circulating_supply = blockchainObj.circulating_supply
    remaining_supply = blockchainObj.get_remaining_supply()
    mined_blocks = len(blockchainObj.chain) - 1  # excluding the genesis block
    total_transactions = sum(len(block.transactions) for block in blockchainObj.chain)

    # Render the HTML template with coin data
    return render_template(
        'coin_metrics.html',
        total_supply=total_supply,
        circulating_supply=circulating_supply,
        remaining_supply=remaining_supply,
        mined_blocks=mined_blocks,
        total_transactions=total_transactions
    )


@app.route('/contract/create', methods=['GET', 'POST'])
@login_required
def create_contract_view():
    if request.method == 'POST':
        contract_type = request.form.get('contract_type')

        # Autogenerate contract_id
        contract_id = str(uuid4())

        # Handle marketplace contract creation
        if contract_type == 'marketplace':
            item_name = request.form.get('item_name')
            price = request.form.get('price')
            creator = current_user.username

            # Validate inputs
            if not item_name or not price:
                flash('All fields are required for a marketplace contract.', 'danger')
                return redirect(url_for('create_contract_view'))

            # Create contract data for the marketplace
            contract_data = json.dumps({
                'type': 'marketplace',
                'rules': [{
                    'action': 'list_item',
                    'item_name': item_name,
                    'price': price,
                }]
            })

            # Create the marketplace contract
            feedback = blockchainObj.create_contract(contract_id, contract_data, creator)
            if feedback:
                flash('Marketplace contract created successfully!', 'success')
                # Redirect to view the created contract
                return redirect(url_for('view_contract_view', contract_id=contract_id))
            else:
                flash('Error creating contract. Contract ID may already exist.', 'danger')

        # Handle conditional transaction creation as a contract
        elif contract_type == 'transaction':
            sender = current_user.username  # Sender is the current user
            receiver = request.form.get('receiver')
            amount = request.form.get('amount')
            condition = request.form.get('condition')

            # Validate inputs
            if not sender or not receiver or not amount:
                flash('All fields are required for a conditional transaction.', 'danger')
                return redirect(url_for('create_contract_view'))

            # Create contract data for the conditional transaction
            contract_data = json.dumps({
                'type': 'conditional_transaction',
                'rules': [{
                    'action': 'transfer',
                    'amount': amount,
                    'to': receiver,
                    'condition': condition
                }]
            })

            # Create the conditional transaction contract
            feedback = blockchainObj.create_contract(contract_id, contract_data, sender)
            if feedback:
                flash('Conditional transaction contract created successfully!', 'success')
                # Redirect to view the created contract
                return redirect(url_for('view_contract_view', contract_id=contract_id))
            else:
                flash('Error creating contract. Contract ID may already exist.', 'danger')

        return redirect(url_for('contract_dashboard_view'))

    # Simply render the form if it's a GET request
    return render_template('create_contract.html')



@app.route('/contract/view/<contract_id>', methods=['GET'])
@login_required
def view_contract_view(contract_id):
    contract = blockchainObj.get_contract(contract_id)
    if contract:
        return render_template('view_contract.html', contract=contract)
    else:
        flash('Contract not found!', 'danger')
        return redirect(url_for('contract_dashboard_view'))


@app.route('/contracts', methods=['GET'])
@login_required
def contract_dashboard_view():
    contracts = blockchainObj.smart_contracts.values()
    logger.debug(f"Contracts passed to template: {list(contracts)}")  # Ensure contracts are logged correctly
    return render_template('contract_dashboard.html', contracts=contracts)


@app.route('/contract/execute', methods=['GET', 'POST'])
@login_required
def execute_contract_view():
    if request.method == 'POST':
        contract_id = request.form.get('contract_id', '').strip()

        # Validate that contract ID is provided
        if not contract_id:
            flash('Contract ID is required to execute a contract.', 'danger')
            return redirect(url_for('execute_contract_view'))

        # Execute the contract in the blockchain
        feedback = blockchainObj.execute_contract(contract_id)

        # Check feedback for success or failure and flash the appropriate message
        if feedback == 'conditional_transfer_executed' or feedback == 'executed_condition_met':
            flash('Conditional transfer executed successfully!', 'success')
            logger.info(f"Executed conditional transfer for contract ID {contract_id}.")
        elif feedback == 'condition_not_met':
            flash('Contract executed, but the condition was not met.', 'warning')
            logger.info(f"Executed contract with ID {contract_id}, but condition not met.")
        elif feedback == 'marketplace_listed':
            flash('Marketplace item listed successfully!', 'success')
            logger.info(f"Listed item for marketplace contract ID {contract_id}.")
        elif feedback == 'already_executed':
            flash('Contract has already been executed.', 'warning')
            logger.info(f"Contract with ID {contract_id} was already executed.")
        else:
            flash('Error executing contract. Please check the contract ID or ensure conditions are met.', 'danger')
            logger.error(f"Failed to execute contract with ID {contract_id}. Feedback received: {feedback}")

        return redirect(url_for('contract_dashboard_view'))

    return render_template('execute_contract.html')


@app.route('/marketplace', methods=['GET'])
@login_required
def marketplace_view():
    items = [
        {
            'contract_id': contract.contract_id,
            'item_name': contract.contract_data['rules'][0]['item_name'],
            'price': contract.contract_data['rules'][0]['price']
        }
        for contract in blockchainObj.smart_contracts.values()
        if contract.is_executed and contract.contract_data.get('type') == 'marketplace' and contract.contract_data.get('status') != 'sold'
    ]
    return render_template('marketplace.html', items=items)


@app.route('/marketplace/purchase', methods=['POST'])
@login_required
def purchase_item():
    contract_id = request.form.get('contract_id', '').strip()
    buyer = current_user.username

    # Check if contract exists and is of type 'marketplace'
    contract = blockchainObj.get_contract(contract_id)
    if contract:
        contract_data = contract.contract_data  # No need to parse as it's already a dictionary
        if contract_data.get('type') == 'marketplace':
            item_name = contract_data['rules'][0]['item_name']
            price = int(contract_data['rules'][0]['price'])  # Convert to int for correct comparison

            # Attempt to purchase item with user's blockchain coins
            feedback = blockchainObj.purchase_item(contract_id, buyer)

            if feedback:
                flash(f"Successfully purchased {item_name} for {price} coins!", 'success')
            else:
                flash("Purchase failed. Please ensure you have enough coins or try again later.", 'danger')
        else:
            flash("Invalid contract type for purchase.", 'danger')
    else:
        flash("Contract not found!", 'danger')

    return redirect(url_for('marketplace_view'))