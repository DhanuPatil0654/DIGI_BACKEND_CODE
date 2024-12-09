const fs = require('fs');
const crypto = require('crypto');
const userModel = require('../modal/modal');
const forge = require('node-forge');
const xmlBuilder = require('xmlbuilder');
const { DateTime } = require('luxon');


const generateTxnAndTs = (id) => {
    const now = DateTime.now().setZone('Asia/Kolkata');
    const currentTimestamp = now.toFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZZ");

    const datePart = now.toFormat('yyyyMMdd');
    const timePart = now.toMillis();
    const randomPart = Math.floor(1000 + Math.random() * 9000);

    const txn = `AD${datePart}${timePart}${randomPart}`;
    return { txn, ts: currentTimestamp };
};



const addUser = async (req, res) => {
    const { signerid } = req.body;
    try {
        // Step 1: Read the uploaded file and compute SHA256 hash
        const filePath = `uploads/${req.file.filename}`;
        const fileBuffer = fs.readFileSync(filePath);
        const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

        // Step 2: Generate txn and ts using the signerid
        const { txn, ts } = generateTxnAndTs(signerid);

        // Step 3: Prepare the document URL
        const docUrl = `http://localhost:8000/uploads/${req.file.filename}`;

        // Step 4: Create user data and save it to the database
        const userData = new userModel({
            signerid: signerid,
            pdfFile: req.file.filename,
            txn,
            ts,  // Store txn and ts in the database
        });

        // Save the data and get the result
        const data = await userData.save();
        console.log("DB Data : ", userData);

        // Step 5: Create the XML document
        const xmlDoc = xmlBuilder.create('Esign', {
            encoding: 'UTF-8',
            standalone: ''
        })
            .att('aspId', 'ProdigiUAT01')
            .att('maxWaitPeriod', '1440')
            .att('redirectUrl', 'https://www.mocky.io/asp/')
            .att('responseUrl', 'https://prodigisignbackend.sumagodemo.com/api/eSignResponse')
            .att('signerid', signerid)
            .att('signingAlgorithm', 'ECDSA')
            .att('ts', ts) // Use ts here
            .att('txn', txn) // Use txn here
            .att('ver', '3.3');

        // Add the document hash to the XML
        xmlDoc.ele('Docs')
            .ele('InputHash', {
                docInfo: 'test document for demo',
                docUrl: docUrl,
                hashAlgorithm: 'SHA256',
                id: '1',
                responseSigType: 'pkcs7',
            })
            .txt(hash)
            .up();

        // Format the XML
        const formattedXML = xmlDoc.end({ pretty: true });

        // Step 6: Save the XML file
        const xmlFilePath = `uploads/${txn}.xml`;
        fs.writeFileSync(xmlFilePath, formattedXML, 'utf8');

        // Step 7: Send a response with the result
        res.status(200).send({
            msg: "PDF uploaded, processed successfully, XML generated and saved",
            data,
            sha256Hash: hash,
            xmlFilePath: xmlFilePath,
        });

    } catch (err) {
        console.error(err);
        res.status(400).send({ msg: "Error processing file", error: err.message });
    }
};






const generateXMLWithSignature = async (req, res) => {
    try {
        const { id } = req.params;

        // const { txn, ts } = generateTxnAndTs(id);

        // Fetch user data
        const userData = await userModel.findById(id);
        if (!userData) return res.status(404).send({ msg: "Document not found" });

        const filePath = `uploads/${userData.pdfFile}`;
        if (!fs.existsSync(filePath)) throw new Error("PDF file not found.");

        const fileBuffer = fs.readFileSync(filePath);
        const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
        const serverHost = req.protocol + "://" + req.get("host");
        const docUrl = `${serverHost}/uploads/${userData.pdfFile}`;

        // Load .pfx file
        const pfxPath = "E:/UAT_Profdigisign_ESP.p12"; // Ensure this path is correct
        if (!fs.existsSync(pfxPath)) throw new Error(".pfx file not found.");



        const pfxBuffer = fs.readFileSync(pfxPath);

        const p12Asn1 = forge.asn1.fromDer(pfxBuffer.toString('binary'));
        const p12Password = '1234'; // Replace with your password
        const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, p12Password);

        // Extract private key and certificate
        const keyBag = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag];
        if (!keyBag || keyBag.length === 0) throw new Error('Private key not found in the .pfx file.');
        const privateKey = keyBag[0].key;

        const certBag = p12.getBags({ bagType: forge.pki.oids.x509CertificateBag })[forge.pki.oids.x509CertificateBag];
        if (!certBag || certBag.length === 0) throw new Error('Certificate not found in the .pfx file.');
        const cert = certBag[0].cert;

        // Prepare certificate and subject name
        const certPem = forge.pki.certificateToPem(cert);
        const cleanedCert = certPem
            .replace(/-----BEGIN CERTIFICATE-----/g, '')
            .replace(/-----END CERTIFICATE-----/g, '')
            .replace(/\s+/g, '');

        const attributesMap = cert.subject.attributes.reduce((acc, attr) => {
            acc[attr.shortName] = attr.value;
            return acc;
        }, {});

        // Dynamically generate the subject name without the predefined order
        // Modify this part where you're dynamically generating the subject name
        const subjectName = Object.keys(attributesMap)
            .filter(key => ['CN', 'O', 'C'].includes(key))  // Filter to only include CN, O, and C
            .sort((a, b) => {  // Sort in the correct order: CN first, then O, then C
                const order = ['CN', 'O', 'C'];
                return order.indexOf(a) - order.indexOf(b);
            })
            .map(key => `${key}=${attributesMap[key]}`)
            .join(',');

        console.log('Subject Name:', subjectName);
        // Generate InputHash reference content
        const referenceContent = `<InputHash docInfo="test document for demo"
   docUrl="${docUrl}"
   hashAlgorithm="SHA256"
   id="1"
   responseSigType="pkcs7">${hash}</InputHash>`;
        const referenceHash = crypto.createHash('sha256').update(referenceContent).digest('base64');

        // Sign the XML content
        const xmlToSign = xmlBuilder.create('Esign', { encoding: 'UTF-8', standalone: '' })
            .att('aspId', 'ProdigiUAT01')
            .att('maxWaitPeriod', '1440')
            .att('redirectUrl', 'https://www.mocky.io/asp/')
            .att('responseUrl', 'https://prodigisignbackend.sumagodemo.com/api/eSignResponse')
            .att('signerid', userData.signerid)
            .att('signingAlgorithm', 'ECDSA')
            .att('ts', userData.ts)
            .att('txn', userData.txn)
            .att('ver', '3.3')
            .ele('Docs')
            .ele('InputHash', {
                docInfo: 'test document for demo',
                docUrl: docUrl,
                hashAlgorithm: 'SHA256',
                id: '1',
                responseSigType: 'pkcs7'
            })
            .txt(hash)
            .up()
            .up();

        const formattedXML = xmlToSign.end({ pretty: true });
        const md = forge.md.sha256.create();
        md.update(formattedXML, 'utf8');
        const signature = privateKey.sign(md);

        // Print the signature, certificate, digest value, and subject name
        console.log("Signature (Base64):", forge.util.encode64(signature));
        console.log("Certificate:", cleanedCert);
        console.log("DigestValue:", referenceHash);
        console.log("Subject Name:", subjectName);

        // Final response XML with signature
        const responseXML = xmlBuilder.create('Esign', { encoding: 'UTF-8', standalone: '' })
            .att('aspId', 'ProdigiUAT01')
            .att('maxWaitPeriod', '1440')
            .att('redirectUrl', 'https://www.mocky.io/asp/')
            .att('responseUrl', 'https://prodigisignbackend.sumagodemo.com/api/eSignResponse')
            .att('signerid', userData.signerid)
            .att('signingAlgorithm', 'ECDSA')
            .att('ts', userData.ts)
            .att('txn', userData.txn)
            .att('ver', '3.3')
            .ele('Docs')
            .ele('InputHash', {
                docInfo: 'test document for demo',
                docUrl: docUrl,
                hashAlgorithm: 'SHA256',
                id: '1',
                responseSigType: 'pkcs7'
            })
            .txt(hash)
            .up()
            .up()
            .ele('Signature', { xmlns: "http://www.w3.org/2000/09/xmldsig#" })
            .ele('SignedInfo')
            .ele('CanonicalizationMethod', { Algorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" })
            .up()
            .ele('SignatureMethod', { Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" })
            .up()
            .ele('Reference', { URI: '' })
            .ele('Transforms')
            .ele('Transform', { Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature" })
            .up()
            .up()
            .ele('DigestMethod', { Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256" })
            .up()
            .ele('DigestValue', referenceHash)
            .up()
            .up()
            .up()
            .ele('SignatureValue', forge.util.encode64(signature))
            .up()
            .ele('KeyInfo')
            .ele('X509Data')
            .ele('X509Certificate').txt(cleanedCert).up()
            .ele('X509SubjectName').txt(subjectName).up()
            .up()
            .up();

        const finalXML = responseXML.end({ pretty: true });
        res.setHeader('Content-Type', 'application/xml');
        res.status(200).send(finalXML);

    } catch (error) {
        console.error('Error in generateXMLWithSignature:', error);
        res.status(500).send({ msg: 'Error generating signed XML', error: error.message });
    }
};
















const findUser = async (req, res) => {
    try {
        const userData = await userModel.find();
        res.status(200).send({ userData });
    } catch (err) {
        res.status(400).send(err);
    }
};
const deletePDF = async (req, res) => {
    try {
        const { id } = req.params;

        // Find the document in the database
        const userData = await userModel.findById(id);

        if (!userData) {
            return res.status(404).send({ msg: "PDF not found" });
        }

        // Path to the uploaded file
        const filePath = `uploads/${userData.pdfFile}`;

        // Delete the file from the filesystem
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }

        // Remove the document from the database
        await userModel.findByIdAndDelete(id);

        res.status(200).send({ msg: "PDF deleted successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).send({ msg: "An error occurred", error: err.message });
    }
};

const txnref = async (req, res) => {
    const transactionID = `TXN-${new Date().getTime()}`; // Example: TXN-1698327163450

    // Define the response code (you can replace this with a dynamic value)
    const responseCode = "b4048ae9c264f268cdf6f5ee0c0a3725"; // Example response code

    // Concatenate the transaction ID and response code with a pipe "|"
    const dataToEncode = `${transactionID}|${responseCode}`;

    // Convert the string to Base64
    const txnref = Buffer.from(dataToEncode).toString('base64');

    // Log the results
    console.log("Transaction ID:", transactionID);
    console.log("Base64 Encoded txnref:", txnref);

};




module.exports = { addUser, findUser, deletePDF, generateXMLWithSignature, txnref, };


