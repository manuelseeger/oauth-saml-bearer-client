using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Xml;
public class Verify {
    public static void Main(String[] args) {
        try
        {
            // Create a new XML document.
            XmlDocument xmlDoc = new XmlDocument();

            // Load an XML file into the XmlDocument object.
            
            xmlDoc.Load(args[0]);

            // Verify the signature of the signed XML.
            Console.WriteLine("Verifying signature...");
            bool result = VerifyXml(xmlDoc);

            // Display the results of the signature verification to
            // the console.
            if (result)
            {
                Console.WriteLine("The XML signature is valid.");
            }
            else
            {
                Console.WriteLine("The XML signature is not valid.");
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
        }
    }
    // Verify the signature of an XML file against an asymmetric
    // algorithm and return the result.
    public static Boolean VerifyXml(XmlDocument xmlDoc)
    {
        // Check arguments.
        if (xmlDoc == null)
             throw new ArgumentException("xmlDoc");

        // Create a new SignedXml object and pass it
        // the XML document class.
        SignedXml signedXml = new SignedXml(xmlDoc);

        // Find the "Signature" node and create a new
        // XmlNodeList object.
        XmlNodeList nodeList = xmlDoc.GetElementsByTagName("Signature");

        // Throw an exception if no signature was found.
        if (nodeList.Count <= 0)
        {
            throw new CryptographicException("Verification failed: No Signature was found in the document.");
        }

        // This example only supports one signature for
        // the entire XML document.  Throw an exception
        // if more than one signature was found.
        if (nodeList.Count >= 2)
        {
            throw new CryptographicException("Verification failed: More that one signature was found for the document.");
        }

        // Load the first <signature> node.
        signedXml.LoadXml(nodeList[0] as XmlElement);

        // Check the signature and return the result.
        return signedXml.CheckSignature();
    }
}