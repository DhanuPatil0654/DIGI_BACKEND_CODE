const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, 'uploads/'); // Upload files to the "uploads" directory
    },
    filename: function (req, file, cb) {
      cb(null, Date.now() + path.extname(file.originalname)); // Set the file name to be unique
    }
  });
  
  // Initialize Multer upload
  const upload = multer({ storage: storage });

  module.exports = upload