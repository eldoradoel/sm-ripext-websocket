methodmap Crypto
{
    public native bool MD5(const char[] source, char[] buffer, int maxlength);

    public native bool MD5File(const char[] file, char[] buffer, int maxlength);

    public native bool SHA1(const char[] source, char[] buffer, int maxlength);

    public native bool SHA1File(const char[] file, char[] buffer, int maxlength);

    public native bool SHA256(const char[] source, char[] buffer, int maxlength);

    public native bool SHA256File(const char[] file, char[] buffer, int maxlength);

    public native bool SHA512(const char[] source, char[] buffer, int maxlength);

    public native bool SHA512File(const char[] file, char[] buffer, int maxlength);

    public native bool CRC16(const char[] source, char[] buffer, int maxlength);

    public native bool CRC16File(const char[] file, char[] buffer, int maxlength);

    public native bool CRC32(const char[] source, char[] buffer, int maxlength, bool hexdecimal = true);

    public native bool CRC32File(const char[] file, char[] buffer, int maxlength, bool hexdecimal = true);
    
};