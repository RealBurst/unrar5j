package be.stef;

import be.stef.rar.Unrar5j;

public class Test {

   public static void main(String[] args) {
      String path = "c:\\test\\rar\\";
      String path4 = "c:\\test\\rar4\\";
      String path5 = "c:\\test\\rar5\\";
      Unrar5j r = new Unrar5j();
      
      //RAR5
      r.extract(path5 + "Solid_Archive.rar", path + "_rar5_01", null);
      r.extract(path5 + "Solid_Archive_Password=toto.rar", path + "_rar5_02", "toto");
      r.extract(path5 + "Blake2_checksum_test.rar", path + "_rar5_03", null);
      r.extract(path5 + "Blake2_password=toto.rar", path + "_rar5_04", "toto");
      r.extract(path5 + "Encrypted + filename Password=toto.rar", path + "_rar5_05", "toto");
      r.extract(path5 + "Encrypted_Password=toto + High Compression.rar", path + "_rar5_06", "toto");
      r.extract(path5 + "Filters_Test - ARM.rar", path + "_rar5_07", null);
      r.extract(path5 + "Filters_Test - E8-E9.rar", path + "_rar5_08", null);
      r.extract(path5 + "Filters_Test_Delta.rar", path + "_rar5_09", null);
      r.extract(path5 + "Rar5.multi.part01.rar", path + "_rar5_10", null);
      r.extract(path5 + "Rar.multi.solid.part01.rar", path + "_rar5_11", null);
      r.extract(path5 + "Rar.multi.encrypted.part01.rar", path + "_rar5_12", "test");
      
      //RAR4
      r.extract(path4 + "Rar4.rar", path + "_rar4_1", null);
      r.extract(path4 + "Rar.solid.rar", path + "_rar4_2", null);
      r.extract(path4 + "Rar.encrypted_filesOnly.rar", path + "_rar4_3", "test");
      r.extract(path4 + "Rar.encrypted_filesAndHeader.rar", path + "_rar4_4", "test");
      r.extract(path4 + "Rar.multi.part01.rar", path + "_rar4_5", null);
      r.extract(path4 + "Rar.EncryptedParts.part01.rar", path + "_rar4_6", "test");
   }
}
