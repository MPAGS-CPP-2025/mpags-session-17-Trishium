//! Unit Tests for MPAGSCipher processCommandLine interface
#include "gtest/gtest.h"

#include "ProcessCommandLine.hpp"
#include "Exceptions.cpp"

TEST(CommandLine, HelpFoundCorrectly)
{
    
    const std::vector<std::string> cmdLine{"mpags-cipher", "--help"};
    const ProgramSettings res{processCommandLine(cmdLine)};

    EXPECT_TRUE(res.helpRequested);
}

TEST(CommandLine, VersionFoundCorrectly)
{
    
    const std::vector<std::string> cmdLine{"mpags-cipher", "--version"};
    const ProgramSettings res{processCommandLine(cmdLine)};

    EXPECT_TRUE(res.versionRequested);
}

TEST(CommandLine, EncryptModeActivated)
{
    
    const std::vector<std::string> cmdLine{"mpags-cipher", "--encrypt"};
    const ProgramSettings res{processCommandLine(cmdLine)};

    
    EXPECT_EQ(res.cipherMode, CipherMode::Encrypt);
}

TEST(CommandLine, DecryptModeActivated)
{
    
    const std::vector<std::string> cmdLine{"mpags-cipher", "--decrypt"};
    const ProgramSettings res{processCommandLine(cmdLine)};

    
    EXPECT_EQ(res.cipherMode, CipherMode::Decrypt);
}

TEST(CommandLine, KeyEnteredWithoutSpecification)
{
    
    const std::vector<std::string> cmdLine{"mpags-cipher", "-k"};
    const ProgramSettings res{processCommandLine(cmdLine)};

    EXPECT_THROW(processCommandLine(cmdLine), MissingArgument);
}

TEST(CommandLine, KeyEnteredAndSpecified)
{
    
    const std::vector<std::string> cmdLine{"mpags-cipher", "-k", "4"};
    const ProgramSettings res{processCommandLine(cmdLine)};

    
    EXPECT_EQ(res.cipherKey.size(), 1);
    EXPECT_EQ(res.cipherKey[0], "4");
}

TEST(CommandLine, InputFileWithoutArg)
{
    
    const std::vector<std::string> cmdLine{"mpags-cipher", "-i"};
    const ProgramSettings res{processCommandLine(cmdLine)};

    EXPECT_THROW(processCommandLine(cmdLine), MissingArgument);
}

TEST(CommandLine, InputFileDeclared)
{
    
    const std::vector<std::string> cmdLine{"mpags-cipher", "-i", "input.txt"};
    const ProgramSettings res{processCommandLine(cmdLine)};

    
    EXPECT_EQ(res.inputFile, "input.txt");
}

TEST(CommandLine, OutputFileWithoutArg)
{
    
    const std::vector<std::string> cmdLine{"mpags-cipher", "-o"};
    const ProgramSettings res{processCommandLine(cmdLine)};

    EXPECT_THROW(processCommandLine(cmdLine), MissingArgument);
}

TEST(CommandLine, OutputFileDeclared)
{
    
    const std::vector<std::string> cmdLine{"mpags-cipher", "-o", "output.txt"};
    const ProgramSettings res{processCommandLine(cmdLine)};

    
    EXPECT_EQ(res.outputFile, "output.txt");
}

TEST(CommandLine, CipherTypeWithoutArg)
{
    
    const std::vector<std::string> cmdLine{"mpags-cipher", "-c"};
    const ProgramSettings res{processCommandLine(cmdLine)};

    EXPECT_THROW(processCommandLine(cmdLine), MissingArgument);
}

TEST(CommandLine, CipherTypeUnknown)
{
    
    const std::vector<std::string> cmdLine{"mpags-cipher", "-c", "rubbish"};
    const ProgramSettings res{processCommandLine(cmdLine)};

    EXPECT_THROW(processCommandLine(cmdLine), CipherDoesNotExist);
}

TEST(CommandLine, CipherTypeCaesar)
{
    
    const std::vector<std::string> cmdLine{"mpags-cipher", "-c", "caesar"};
    const ProgramSettings res{processCommandLine(cmdLine)};

    
    EXPECT_EQ(res.cipherType.size(), 1);
    EXPECT_EQ(res.cipherType[0], CipherType::Caesar);
}

TEST(CommandLine, CipherTypePlayfair)
{
    
    const std::vector<std::string> cmdLine{"mpags-cipher", "-c", "playfair"};
    const ProgramSettings res{processCommandLine(cmdLine)};

    
    EXPECT_EQ(res.cipherType.size(), 1);
    EXPECT_EQ(res.cipherType[0], CipherType::Playfair);
}

TEST(CommandLine, CipherTypeVigenere)
{
    
    const std::vector<std::string> cmdLine{"mpags-cipher", "-c", "vigenere"};
    const ProgramSettings res{processCommandLine(cmdLine)};

   
    EXPECT_EQ(res.cipherType.size(), 1);
    EXPECT_EQ(res.cipherType[0], CipherType::Vigenere);
}

TEST(CommandLine, MultiCipherWithoutArg)
{
    
    const std::vector<std::string> cmdLine{"mpags-cipher", "--multi-cipher"};
    const ProgramSettings res{processCommandLine(cmdLine)};

    EXPECT_THROW(processCommandLine(cmdLine), UnexpectedQuantity);
}

TEST(CommandLine, MultiCipherInvalidArg)
{
    
    const std::vector<std::string> cmdLine{"mpags-cipher", "--multi-cipher",
                                           "a"};
    const ProgramSettings res{processCommandLine(cmdLine)};

    EXPECT_THROW(processCommandLine(cmdLine), MissingArgument);
}

TEST(CommandLine, MultiCipherMismatchedArgs)
{
    
    const std::vector<std::string> cmdLine{
        "mpags-cipher", "--multi-cipher", "2", "-c", "caesar", "-k", "23"};
    const ProgramSettings res{processCommandLine(cmdLine)};

    EXPECT_THROW(processCommandLine(cmdLine), UnexpectedQuantity);
}

TEST(CommandLine, MultiCipherMatchedArgs)
{
    
    const std::vector<std::string> cmdLine{"mpags-cipher",
                                           "--multi-cipher",
                                           "2",
                                           "-c",
                                           "caesar",
                                           "-k",
                                           "23",
                                           "-c",
                                           "playfair",
                                           "-k",
                                           "playfairexample"};
    const ProgramSettings res{processCommandLine(cmdLine)};

    
    EXPECT_EQ(res.cipherType.size(), 2);
    EXPECT_EQ(res.cipherType[0], CipherType::Caesar);
    EXPECT_EQ(res.cipherType[1], CipherType::Playfair);
    EXPECT_EQ(res.cipherKey.size(), 2);
    EXPECT_EQ(res.cipherKey[0], "23");
    EXPECT_EQ(res.cipherKey[1], "playfairexample");
}
