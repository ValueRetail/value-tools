using System.IO;
using System;

namespace Value.Tools
{
    public class FileTools
    {
        public static string GetCurrentFilePath(string fileName)
        {
            if (string.IsNullOrEmpty(fileName))
            {
                throw new ArgumentException("The file name cannot be null or empty", nameof(fileName));
            }

            string currentDirectory = Directory.GetCurrentDirectory();
            string filePath = Path.Combine(currentDirectory, fileName);

            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("The specified file does not exist", filePath);
            }

            return filePath;
        }
    }
}