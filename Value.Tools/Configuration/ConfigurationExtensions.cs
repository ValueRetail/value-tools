using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml.Linq;
using System.Xml;
using System.Configuration;
using Microsoft.Extensions.Configuration;
using Value.Tools.Configuration;
using Value.Tools.Security;
using Newtonsoft.Json.Linq;
using System.Linq;

namespace Value.Tools.Configuration
{
    public static class ConfigurationExtensions
    {
        public static IConfiguration Decrypt(this IConfiguration root, string keyPath, string cipherPrefix)
        {
            var secret = root[keyPath] ?? throw new ArgumentNullException(nameof(keyPath), "Secret could not be found in environment variables. Please check the keyPath and try again.");
            var cipher = new AES256Cipher(secret);
            EncryptIfNeededAndDecryptInChildren(root);
            return root;

            void EncryptIfNeededAndDecryptInChildren(IConfiguration parent)
            {
                foreach (var child in parent.GetChildren())
                {
                    if (child.Value?.StartsWith(cipherPrefix) == true)
                    {
                        var cipherText = child.Value.Substring(cipherPrefix.Length);
                        parent[child.Key] = cipher.Decrypt(cipherText);
                    }
                    EncryptIfNeededAndDecryptInChildren(child);
                }
            }
        }

        public static IConfigurationBuilder AddAndEncryptJsonFile(this Microsoft.Extensions.Configuration.ConfigurationManager builder, string path, bool optional, bool reloadOnChange, string keyPath, string cipherPrefix, string[] encryptKeysRegEx)
        {
            if (!File.Exists(path) && !optional)
                throw new FileNotFoundException("Configuration file not found", path);
            if (!File.Exists(path) && optional)
                return builder.AddJsonFile(null, path, optional, reloadOnChange);

            var secret = builder[keyPath] ?? throw new ArgumentNullException(nameof(keyPath), "Secret could not be found in environment variables. Please check the keyPath and try again.");
            var cipher = new AES256Cipher(secret);

            var data = File.ReadAllText(path);
            var rss = JObject.Parse(data);
            var modified = false;
            foreach (var j in rss.Descendants().OfType<JProperty>())
            {
                foreach (var pattern in encryptKeysRegEx)
                {
                    if (System.Text.RegularExpressions.Regex.IsMatch(j.Path, pattern) &&
                        !j.Value.ToString().StartsWith(cipherPrefix))
                    {
                        j.Value = cipherPrefix + cipher.Encrypt(j.Value.ToString());
                        modified = true;
                    }
                }
            }
            if (modified)
                File.WriteAllText(path, rss.ToString(Newtonsoft.Json.Formatting.Indented));
            return builder.AddJsonFile(null, path, optional, reloadOnChange);
        }

        public static IConfigurationBuilder AddAndEncryptXmlFile(this Microsoft.Extensions.Configuration.ConfigurationManager builder, string path, bool optional, bool reloadOnChange, string keyPath, string cipherPrefix, string[] encryptKeysXPaths)
        {
            if (!File.Exists(path) && !optional)
                throw new FileNotFoundException("Configuration file not found", path);
            if (!File.Exists(path) && optional)
                return builder.AddXmlFile(null, path, optional, reloadOnChange);

            var secret = builder[keyPath] ?? throw new ArgumentNullException(nameof(keyPath), "Secret could not be found in environment variables. Please check the keyPath and try again.");
            var cipher = new AES256Cipher(secret);

            var data = File.ReadAllBytes(path);
            var modified = false;

            if (Path.GetExtension(path).Equals(".xml", StringComparison.OrdinalIgnoreCase))
            {
                using (var stream = new MemoryStream(data))
                {
                    using (var xmlReader = new XmlTextReader(stream))
                    {
                        xmlReader.MoveToContent();
                        var namespaces = xmlReader.GetNamespacesInScope(XmlNamespaceScope.All);

                        var xmlDoc = new XmlDocument
                        {
                            PreserveWhitespace = true,
                        };
                        xmlDoc.Load(xmlReader);

                        var nsMgr = new XmlNamespaceManager(xmlDoc.NameTable);
                        foreach (var ns in namespaces)
                        {
                            nsMgr.AddNamespace(
                                string.IsNullOrWhiteSpace(ns.Key) ? "x" : ns.Key,
                                ns.Value);
                        }

                        var xmlRoot = xmlDoc.DocumentElement;
                        if (xmlRoot != null)
                            foreach (string xPath in encryptKeysXPaths)
                            {
                                if (!string.IsNullOrWhiteSpace(xPath))
                                {
                                    try
                                    {
                                        var nodes = xmlDoc.SelectNodes(xPath, nsMgr);
                                        if (nodes == null) continue;

                                        foreach (XmlNode node in nodes)
                                        {
                                            if (node is XmlAttribute attributeNode)
                                            {
                                                if (attributeNode?.Value != null &&
                                                    !string.IsNullOrWhiteSpace(attributeNode.Value) &&
                                                    !attributeNode.Value.StartsWith(cipherPrefix) == true)
                                                {
                                                    attributeNode.Value = cipherPrefix + cipher.Encrypt(attributeNode.Value);
                                                    modified = true;
                                                }
                                            }
                                            else if (node is XmlElement elementNode)
                                            {
                                                if (elementNode?.InnerText != null &&
                                                    !string.IsNullOrWhiteSpace(elementNode.InnerText) &&
                                                    !elementNode.InnerText.StartsWith(cipherPrefix) == true)
                                                {
                                                    elementNode.InnerText = cipherPrefix + cipher.Encrypt(elementNode.InnerText);
                                                    modified = true;
                                                }
                                            }
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine(ex.Message);
                                    }
                                }
                            }
                        if (modified)
                            File.WriteAllText(path, xmlDoc.OuterXml);
                    }
                }
            }

            return builder.AddXmlFile(null, path, optional, reloadOnChange);
        }
    }
}
