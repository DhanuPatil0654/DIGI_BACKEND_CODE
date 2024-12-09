const { addUser, findUser, generateXMLWithHash , deletePDF , generateXMLWithSignature, txnref} = require('./controller/control');
const express = require('express');
const router = express();

const pdfUpload = require('./pdfUpload');

// PDF Upload and SHA256 Hash Calculation
router.post('/uploadpdf', pdfUpload.single('pdfFile'), addUser);

// Get All Data
router.get('/findall', findUser);


// router.get('/generateXML/:id', generateXMLWithHash);

router.get('/generateXML/signature/:id', generateXMLWithSignature);

router.delete('/deletepdf/:id', deletePDF);

// router.post('/signture' , signXMLWithPFX)

router.get('/txnref', txnref);


module.exports = router;
