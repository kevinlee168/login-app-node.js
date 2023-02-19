const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');

// Load User model
const User = require('../models/User');
const { forwardAuthenticated } = require('../config/auth');

// Login page
router.get('/login', forwardAuthenticated, (req, res) => res.render('login'));

// Register Page
router.get('/register', forwardAuthenticated, (req, res) => res.render('register'));

// to register a user
router.post('/register', (req, res) => {
    const { name, email, password, password2 } = req.body;  
    
    let errors = [];

    if (!name || !email || !password || !password2) {
        errors.push({ msg: 'Please enter all fields.' });
    }

    if (password != password2) {
        errors.push({ msg: 'Passwords do not match.' });
    }

    if (password.length < 6) {
        errors.push({ msg: 'Password must be at least 6 characters.' });
    }

    if (errors.length > 0) {
        res.render('register', {
            errors,
            name,
            password,
            password2
        });
    } else {
        // Query MongoDB
        User.findOne({ email: email })
            .then(user => {
                if (user) {  // Email already exists
                    errors.push({ msg: 'Email already exists' });
                    res.render('register', {
                        errors,
                        name,
                        password,
                        password2
                    });
                } else { // prepare to add a new user
                    const newUser = new User({
                        name,
                        email,
                        password
                    });

                    // to crypt the password to save it in DB.
                    bcrypt.genSalt(10, (err, salt) => {
                        bcrypt.hash(newUser.password, salt, (err, hash) => {
                            if (err) throw err;
                            newUser.password = hash;  
                            // insert a new user info into db
                            newUser.save()
                                .then(user => {
                                    req.flash('success_msg', 'Registered successfully!');
                                    res.redirect('/users/login');
                                }).catch(err => console.log(err));
                        });
                    });
                }
            });
    } // else
});

// To login
router.post('/login', (req, res, next) => {
    // use passport to verify the login info.
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req, res, next);
});

// To logout
router.get('/logout', (req, res) => {
    req.logout(function(err) { if(err) throw err; });
    // req.logout(); // there is an Error: req#logout requires a callback function
    req.flash('success_msg', 'Logged out successfully.');
    res.redirect('/users/login');
});

module.exports = router;