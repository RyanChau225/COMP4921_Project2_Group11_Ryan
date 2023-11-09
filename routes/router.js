const router = require('express').Router();

const database = include('databaseConnectionMongoDB');
var ObjectId = require('mongodb').ObjectId;

const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');



const cloudinary = require('cloudinary');
cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
  api_key: process.env.CLOUDINARY_CLOUD_KEY,
  api_secret: process.env.CLOUDINARY_CLOUD_SECRET
});
const mongoose = require('mongoose');

const bodyparser = require('body-parser');


const bcrypt = require('bcrypt');
const {
    render
} = require('express/lib/response');
const session = require('express-session');
const MongoStore = require('connect-mongodb-session')(session);
const express = require('express');
const passwordComplexity = require("joi-password-complexity");

const complexityOptions = {
  min: 10,            // Minimum length
  max: 30,            // Maximum length (adjust as needed)
  lowerCase: 1,       // Require at least 1 lowercase letter
  upperCase: 1,       // Require at least 1 uppercase letter
  numeric: 1,         // Require at least 1 digit
  symbol: 1,          // Require at least 1 special character
  requirementCount: 4, // Total number of requirements to satisfy
};

const req = require('express/lib/request');
const ejs = require('ejs');
const multer  = require('multer')
const storage = multer.memoryStorage()
const upload = multer({ storage: storage });

const mongodb_database = process.env.REMOTE_MONGODB_DATABASE;
const userCollection = database.db(mongodb_database).collection('users');
const threadCollection = database.db(mongodb_database).collection('thread');
const commentsCollection = database.db(mongodb_database).collection('comments');


const imageCollection = database.db(mongodb_database).collection('images');


const Joi = require("joi");
const mongoSanitize = require('express-mongo-sanitize');

router.use(mongoSanitize(
    {replaceWith: '%'}
));

const secret_token = process.env.SECRET_TOKEN

async function incrementThreadViews(threadId) {
  try {
    await threadCollection.updateOne(
      { _id: new ObjectId(threadId) },
      { $inc: { views: 1 } } // Increment the views field by 1
    );
  } catch (error) {
    console.error(`An error occurred when incrementing thread views: ${error}`);
  }
}


router.use((req, res, next) => {
	// Set Expires header to a past date
	res.header('Expires', '-1');
	// Set other cache control headers
	res.header('Cache-Control', 'no-cache, private, no-store, must-revalidate');
	next();
  });

router.use(session({
    secret: `${secret_token}`,
    saveUninitialized: true,
    resave: true
}));

router.use((req, res, next) => {
  if (req.session && req.session.user_id) {
      req.user_id = req.session.user_id;
  }
  next();
});




// Middleware to add user_id to res.locals for access in all templates
router.use((req, res, next) => {
  if (req.session && req.session.user_id) {
    res.locals.user_id = req.session.user_id;
  } else {
    res.locals.user_id = null;
  }
  next();
});

router.get('/profile', requireAuthentication, async (req, res) => {
  try {
    // Assuming the user's information is stored in the session or can be retrieved using the user_id
    const user = await userCollection.findOne({ _id: new ObjectId(req.session.user_id) });
    if (!user) {
      res.render('error', { message: 'User not found' });
      return;
    }

    // Set the profilePicUrl to the Cloudinary image URL
    const profilePicUrl = user.profile_picture; // Assuming the profile picture URL is stored in the user's data

    // Render the profile page and pass the user information to the template
    res.render('profile.ejs', {
      email: user.email,
      name: user.first_name + ' ' + user.last_name,
      display_name: user.display_name,
      profilePicUrl: profilePicUrl, // Pass the profile picture URL to the template
    });
  } catch (ex) {
    res.render('error', { message: 'Error fetching user profile' });
    console.error("Error fetching user profile", ex);
  }
});

router.get('/user-threads', requireAuthentication, async (req, res) => {
  try {
    // Check if the user is correctly authenticated
    console.log('User ID:', req.session.user_id);

    // Fetch all threads from the database
    const allThreads = await threadCollection.find({}).toArray();

    // Filter threads that match the user's user_id
    const userThreads = allThreads.filter(thread => thread.user_id === req.session.user_id);

    // Log the retrieved threads for debugging
    console.log('User Threads:', userThreads);

    // Render the user-threads.ejs template with user-specific threads
    res.render('user-threads.ejs', { threads: userThreads });
  } catch (ex) {
    // Log and handle errors
    console.error("Error fetching user threads", ex);
    res.render('error', { message: 'Error fetching user threads' });
  }
});




router.post('/delete-thread/:threadId', requireAuthentication, async (req, res) => {
  const threadId = req.params.threadId;

  try {
    // Check if the thread exists and is owned by the logged-in user
    const thread = await threadCollection.findOne({ _id: new ObjectId(threadId), user_id: req.session.user_id });

    if (!thread) {
      res.render('error', { message: 'Thread not found or unauthorized' });
      return;
    }

    // Delete the thread
    await threadCollection.deleteOne({ _id: new ObjectId(threadId) });

    // Redirect the user back to the user-threads page after deletion
    res.redirect('/user-threads');
  } catch (ex) {
    res.render('error', { message: 'Error deleting thread' });
    console.error("Error deleting thread", ex);
  }
});

function buildCommentTree(comments, parentId = null) {
  let commentTree = [];
  comments.forEach(comment => {
    if (comment.parent_id === parentId) {
      let children = buildCommentTree(comments, comment._id);
      if (children.length) {
        comment.children = children;
      }
      commentTree.push(comment);
    }
  });
  return commentTree;
}


router.use(async (req, res, next) => {
  if (req.session.user_id) {
    try {
      // Ensure the user ID is converted to an ObjectId
      const userId = new ObjectId(req.session.user_id);
      // Fetch only the profile_pic field from the user document
      const user = await userCollection.findOne({ _id: userId }, { projection: { profile_pic: 1 } });
      
      if (user && user.profile_pic) {
        // Set the profilePicUrl if the user has a profile picture
        res.locals.profilePicUrl = user.profile_pic;
      } else {
        // Set to a default profile picture if the user does not have a profile picture
        res.locals.profilePicUrl = './css/codioful-formerly-gradienta-LeG68PrXA6Y-unsplash.jpg'; 
      }
    } catch (error) {
      console.error('Error fetching user profile picture:', error);
      // In case of any error, set a default profile picture
      res.locals.profilePicUrl = './css/codioful-formerly-gradienta-LeG68PrXA6Y-unsplash.jpg'; 
    }
  } else {
    // If no user is logged in, set a default profile picture
    res.locals.profilePicUrl = './css/codioful-formerly-gradienta-LeG68PrXA6Y-unsplash.jpg'; 
  }
  next(); // Proceed to the next middleware or route handler
});


// Home page route
router.get('/', async (req, res) => {
  try {
      // Fetch threads from the database
      const threads = await threadCollection.find().toArray();

      // Fetch the display names for the authors of each thread
      const threadsWithAuthors = await Promise.all(threads.map(async (thread) => {
          const author = await userCollection.findOne({ _id: thread.user_id });
          return {
              ...thread, // spread the thread object
              author: author ? author.display_name : 'Anonymous', // add author display name
              likesCount: thread.likes ? thread.likes.length : 0, // Add likes count
              hasLiked: thread.likes ? thread.likes.includes(req.session.user_id) : false, // Check if current user has liked
              views: thread.views || 0 // Add the views count, defaulting to 0 if it doesn't exist
          };
      }));

      // Rendering the homepage view with threads, their authors, and view counts
      res.render("home-page.ejs", {
          threads: threadsWithAuthors,
          user_id: req.session.user_id // pass the user_id to the template
      });
  } catch (ex) {
      res.render('error', { message: 'Error fetching threads from MongoDB' });
      console.log("Error fetching threads from MongoDB");
      console.log(ex);
  }
});





// Login page routes
router.get('/login', (req, res) => {
  res.render('login', {
    error: 'Invalid login credentials' // Only set this if there's an actual error
  });
});

// Create a post view route
router.get('/create-post', (req, res) => {
  res.render('create-post', { authenticated: req.session.authenticated, user_id: req.user_id });

});





router.get('/my-threads', requireAuthentication, async (req, res) => {
  try {
      const userThreads = await threadCollection.find({ user_id: new ObjectId(req.session.user_id) }).toArray();
      res.render('user-threads', { threads: userThreads });
  } catch (ex) {
      res.render('error', { message: 'Error fetching threads' });
      console.error("Error fetching threads", ex);
  }
});


router.post('/addThread', requireAuthentication, async (req, res) => {
  try {
      console.log("Adding a thread");

      const { user_id, title, content } = req.body;

      // Create schema for validation
      const threadSchema = Joi.object({
          user_id: Joi.string().alphanum().min(24).max(24).required(),
          title: Joi.string().min(1).max(200).required(),
          content: Joi.string().min(1).required(),
          created_at: Joi.date()
      });

      // Validate the request data
      const validationResult = threadSchema.validate({
          user_id,
          title,
          content,
          created_at: new Date()
      });

      if (validationResult.error != null) {
          console.log(validationResult.error);
          return res.render('error', { message: 'Invalid data provided' });
      }

      // Create thread object with likes and views
      const threadDocument = {
          user_id: new ObjectId(user_id),
          title,
          content,
          created_at: new Date(),
          comment_ids: [],
          likes: [],
          views: 0
      };

      // Insert the thread into the database
      const result = await threadCollection.insertOne(threadDocument);

      res.redirect(`/post-detail/${result.insertedId}`);

  } catch (ex) {
      res.render('error', { message: 'Error connecting to MongoDB' });
      console.log("Error connecting to MongoDB");
      console.log(ex);
  }
});

router.post('/toggle-like/:id', requireAuthentication, async (req, res) => {
  const threadId = req.params.id;
  const userId = req.session.user_id;
  
  try {
    // Attempt to find the thread by ID
    const thread = await threadCollection.findOne({ _id: new ObjectId(threadId) });
    
    // If the thread doesn't exist, send a 404 response
    if (!thread) {
      return res.status(404).json({ success: false, message: 'Thread not found' });
    }

    // Determine if the user has already liked the thread
    const hasLiked = thread.likes.includes(userId);

    // Prepare the update operation
    let update;
    if (hasLiked) {
      // If the user has already liked the thread, remove their like
      update = { $pull: { likes: userId } };
    } else {
      // If the user hasn't liked the thread yet, add their like
      update = { $push: { likes: userId } };
    }

    // Apply the update to the thread
    await threadCollection.updateOne({ _id: new ObjectId(threadId) }, update);

    // Fetch the updated thread to get the new like count
    const updatedThread = await threadCollection.findOne({ _id: new ObjectId(threadId) });
    const newLikeCount = updatedThread.likes.length;

    // Respond with the new like count and the user's like status
    res.json({ success: true, newLikeCount, isLiked: !hasLiked });
  } catch (error) {
    // Log the error and respond with a 500 status code for server error
    console.error('Error toggling like status:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});




router.post('/submit-comment/:id', requireAuthentication, async (req, res) => {
  try {
      console.log("Adding a comment or reply");
      
      const { user_id, thread_id, comment: content, parent_comment_id } = req.body;

      // Create schema for validation
      const commentSchema = Joi.object({
          user_id: Joi.string().alphanum().min(24).max(24).required(),
          thread_id: Joi.string().alphanum().min(24).max(24).required(),
          parent_comment_id: Joi.string().alphanum().min(24).max(24).allow(null).optional(),
          content: Joi.string().min(1).required(),
          created_at: Joi.date()
      });

      // Validate the request data
      const validationResult = commentSchema.validate({
          user_id,
          thread_id,
          parent_comment_id: parent_comment_id || null,
          content,
          created_at: new Date()
      });

      if (validationResult.error != null) {
          console.log(validationResult.error);
          return res.render('error', { message: 'Invalid data provided' });
      }

      // Create comment object with likes
      const commentDocument = {
          user_id: new ObjectId(user_id),
          thread_id: new ObjectId(thread_id),
          parent_comment_id: parent_comment_id ? new ObjectId(parent_comment_id) : null,
          content,
          created_at: new Date(),
          likes: []
      };

      // Insert the comment or reply into the database
      const result = await commentsCollection.insertOne(commentDocument);

      if (parent_comment_id) {
          // If it's a reply, update the parent comment's replies array
          await commentsCollection.updateOne(
              { _id: new ObjectId(parent_comment_id) },
              { $push: { replies: result.insertedId } }
          );
      } else {
          // If it's a top-level comment, update the thread's comment_ids array
          await threadCollection.updateOne(
              { _id: new ObjectId(thread_id) },
              { $push: { comment_ids: result.insertedId } }
          );
      }

      res.redirect(`/post-detail/${thread_id}`);
  } catch (ex) {
      res.render('error', { message: 'Error connecting to MongoDB' });
      console.log("Error connecting to MongoDB", ex);
  }
});



router.get('/post-detail/:id', async (req, res) => {
  try {
    const threadId = req.params.id;

    await incrementThreadViews(threadId);

    // Validate threadId
    if (!threadId || threadId.length !== 24) {
        return res.render('error', { message: 'Invalid thread ID' });
    }

    const thread = await threadCollection.findOne({ _id: new ObjectId(threadId) });
    if (!thread) {
        return res.render('error', { message: 'Thread not found' });
    }

    // Fetch the display name of the thread's author.
    const threadAuthor = await userCollection.findOne({ _id: new ObjectId(thread.user_id) });
    const threadAuthorDisplayName = threadAuthor ? threadAuthor.display_name : 'Anonymous';

    // Fetch comments related to this thread. 
    const comments = await commentsCollection.find({ thread_id: new ObjectId(threadId) }).toArray();
    
    const userIdInSession = req.session.user_id;

    // Get display names and like counts for each comment's author.
    const commentsWithAuthorsAndLikes = await Promise.all(comments.map(async (comment) => {
        const commentAuthor = await userCollection.findOne({ _id: new ObjectId(comment.user_id) });
        return {
            ...comment,
            author: commentAuthor ? commentAuthor.display_name : 'Anonymous',
            likesCount: comment.likes ? comment.likes.length : 0,
            hasLiked: comment.likes && userIdInSession ? comment.likes.includes(userIdInSession) : false,
        };
    }));

    // Render the post-detail view
    res.render('post-detail', {
      post: {
          title: thread.title,
          content: thread.content,
          author: threadAuthorDisplayName,
          comments: commentsWithAuthorsAndLikes,
          id: threadId,
          likes: thread.likes || [], // Include likes array
          likesCount: thread.likes ? thread.likes.length : 0,
          hasLiked: thread.likes && userIdInSession ? thread.likes.includes(userIdInSession) : false, // Determine if the user has liked the post
          user_id: userIdInSession || null
      }
    });
  } catch (ex) {
    res.render('error', { message: 'Error fetching thread details' });
    console.log("Error fetching thread details", ex);
  }
});



router.post('/toggle-comment-like', async (req, res) => {
  const { commentId, userId } = req.body;

  // Retrieve the comment from the database
  const comment = await commentsCollection.findOne({ _id: ObjectId(commentId) });

  // Check if the user has already liked the comment
  const hasLiked = comment.likes.includes(userId);

  if (hasLiked) {
    // User has liked the comment, so we remove their like
    await commentsCollection.updateOne(
      { _id: ObjectId(commentId) },
      { $pull: { likes: userId } }
    );
  } else {
    // User has not liked the comment, so we add their like
    await commentsCollection.updateOne(
      { _id: ObjectId(commentId) },
      { $addToSet: { likes: userId } }
    );
  }

  // Send a response back to the client
  res.json({ success: true, hasLiked: !hasLiked });
});




router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
      const user = await userCollection.findOne({ email });
      if (!user) {
          throw new Error('Invalid email or password');
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
          throw new Error('Invalid email or password');
      }

      req.session.authenticated = true;
      req.session.user_id = user._id.toString();    // Ensure user_id is set in the session
      console.log("Session after login:", req.session);

      return res.redirect('/');  // Redirect to homepage after successful login


  } catch (error) {
      console.error("Error during login:", error.message);
      return res.render('login', { message: error.message });
  }
});



router.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        res.redirect('/'); 
    });
});

function requireAuthentication(req, res, next) {
  if (!req.session.authenticated) {
      console.log("Authentication required");
      return res.redirect('/login');
  }
  next();
}


  

  
  
  router.get('/showImage', async (req, res) => {
	console.log("page hit");
	try {
		let user_id = req.query.id;
		console.log("user_id: " + user_id);
  
		// Joi validate
		const schema = Joi.object({
			user_id: Joi.string().alphanum().min(24).max(24).required()
		});
  
		const validationResult = schema.validate({ user_id });
		if (validationResult.error != null) {
			console.log(validationResult.error);
			res.render('error', { message: 'Invalid user_id' });
			return;
		}
  
		// Fetch media based on user_id
		const media = await mediaCollection.find({ "user_id": new ObjectId(user_id) }).toArray();
		if (media === null) {
			res.render('error', { message: 'Error connecting to MongoDB' });
			console.log("Error connecting to media collection");
		}
		else {
			console.log(media);
			res.render('addImage', { allMedias: media, user_id: user_id });  // _id can be accessed directly in your media.ejs file
		}
	}
	catch (ex) {
		res.render('error', { message: 'Error connecting to MongoDB' });
		console.log("Error connecting to MongoDB");
		console.log(ex);
	}
  });
  

router.get('/pic', async (req, res) => {
	  res.send('<form action="picUpload" method="post" enctype="multipart/form-data">'
    + '<p>Public ID: <input type="text" name="title"/></p>'
    + '<p>Image: <input type="file" name="image"/></p>'
    + '<p><input type="submit" value="Upload"/></p>'
    + '</form>');
});

router.post('/picUpload', upload.single('image'), function(req, res, next) {
	let buf64 = req.file.buffer.toString('base64');
  stream = cloudinary.uploader.upload("data:image/png;base64," + buf64, function(result) { //_stream
    console.log(result);
    res.send('Done:<br/> <img src="' + result.url + '"/><br/>' +
             cloudinary.image(result.public_id, { format: "png", width: 100, height: 130, crop: "fit" }));
  }, { public_id: req.body.title } );
  console.log(req.body);
  console.log(req.file);

});


router.post('/setmediaPic', upload.single('image'), function(req, res, next) {
	let image_uuid = uuid();
	let media_id = req.body.media_id;
	let user_id = req.body.user_id;
	let buf64 = req.file.buffer.toString('base64');
	stream = cloudinary.uploader.upload("data:image/octet-stream;base64," + buf64, async function(result) { 
			try {
				console.log(result);

				console.log("user_id: "+user_id);


				// Joi validate
				const schema = Joi.object(
				{
					media_id: Joi.string().alphanum().min(24).max(24).required(),
					user_id: Joi.string().alphanum().min(24).max(24).required()
				});
			
				const validationResult = schema.validate({media_id, user_id});
				if (validationResult.error != null) {
					console.log(validationResult.error);

					res.render('error', {message: 'Invalid media_id or user_id'});
					return;
				}				
				const success = await mediaCollection.updateOne({"_id": new ObjectId(media_id)},
					{$set: {image_id: image_uuid}},
					{}
				);

				if (!success) {
					res.render('error', {message: 'Error uploading media image to MongoDB'});
					console.log("Error uploading media image");
				}
				else {
					res.redirect(`/showMedia?id=${user_id}`);
				}
			}
			catch(ex) {
				res.render('error', {message: 'Error connecting to MongoDB'});
				console.log("Error connecting to MongoDB");
				console.log(ex);
			}
		}, 
		{ public_id: image_uuid }
	);
	console.log(req.body);
	console.log(req.file);
});


// Route to render the profile picture upload form
router.get('/updateProfilePic', requireAuthentication, async (req, res) => {
  res.render('updateProfilePic'); // This will be your ejs template for uploading pictures
});

// Route to handle the profile picture upload
router.post('/updateProfilePic', requireAuthentication, upload.single('profile_pic'), async (req, res) => {
  try {
    // Convert buffer to base64
    let buf64 = req.file.buffer.toString('base64');
    
    // Upload the image to Cloudinary
    let result = await cloudinary.uploader.upload(`data:image/png;base64,${buf64}`, {
      folder: "profile_pictures", // You can specify a folder name here
      public_id: `profile_${req.user_id}` // This ensures the name of the file is linked with the user
    });

    // Once the image is uploaded, save the reference URL to the user's document in MongoDB
    await userCollection.updateOne(
      { _id: new ObjectId(req.user_id) },
      { $set: { profile_picture: result.secure_url } } // Save the URL of the uploaded image
    );

    // Redirect to the profile page or render a success message
    res.redirect('/profile');
  } catch (error) {
    console.error('Error uploading profile picture:', error);
    res.render('error', { message: 'Error uploading profile picture' });
  }
});



router.post('/addUser', upload.single('profile_pic'), async (req, res) => {
  try {
    console.log("form submit");
console.log(req.file);

    const saltRounds = 10;

    // Extend your Joi schema to include the profile_pic
    const schema = Joi.object({
      first_name: Joi.string().alphanum().min(2).max(50).required(),
      last_name: Joi.string().alphanum().min(2).max(50).required(),
      email: Joi.string().email().min(2).max(150).required(),
      password: passwordComplexity(complexityOptions).required(),
      display_name: Joi.string().min(2).max(50).required(),
      // profile_pic is optional, so it may not be included in the request
    });

    const validationResult = schema.validate({
      first_name: req.body.first_name,
      last_name: req.body.last_name,
      email: req.body.email,
      password: req.body.password,
      display_name: req.body.display_name,
      // Do not validate the profile picture here since it's being handled separately
    });

    if (validationResult.error != null) {
      console.log(validationResult.error);
      res.render('error', { message: validationResult.error.details[0].message });
      return;
    }

    // Check if the user already exists
    const existingUser = await userCollection.findOne({ email: req.body.email });
    if (existingUser) {
      return res.render('error', { message: 'User with this email already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);

    // Initialize the profile_pic_url to null
    let profile_pic_url = null;

    // If a profile picture was uploaded, process it
    if (req.file) {
      const buf64 = req.file.buffer.toString('base64');
      const imageUploadResponse = await cloudinary.uploader.upload(`data:image/png;base64,${buf64}`, {
        folder: "profile_pictures",
        public_id: `profile_${req.body.email}` // A unique ID for the image
      });
      profile_pic_url = imageUploadResponse.secure_url;
    }

    // Create a new user object with all the information
    const newUser = {
      first_name: req.body.first_name,
      last_name: req.body.last_name,
      email: req.body.email,
      password: hashedPassword,
      display_name: req.body.display_name,
      profile_pic: profile_pic_url // Use the Cloudinary URL or null if no picture was uploaded
    };

    // Insert the new user into the database
    await userCollection.insertOne(newUser);

    // Redirect to the login page after successful registration
    res.redirect("/login");

  } catch (ex) {
    res.render('error', { message: 'Error connecting to MongoDB' });
    console.log("Error connecting to MongoDB");
    console.log(ex);
  }
});


  






// Render signup.ejs
router.get('/signup', (req, res) => {
    res.render("signup.ejs");
})


router.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})




module.exports = router;
