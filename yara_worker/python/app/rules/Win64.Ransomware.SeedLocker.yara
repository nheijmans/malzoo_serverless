rule Win64_Ransomware_SeedLocker : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "SEEDLOCKER"
        description         = "Yara rule that detects SeedLocker ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "SeedLocker"
        tc_detection_factor = 5

    strings:

        $search_files = {
            48 89 5C 24 ?? 48 89 7C 24 ?? 55 48 8D AC 24 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 48 8B 
            05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ?? 48 8B F9 4C 8D 05 ?? ?? ?? ?? 4C 8B C9 
            BA ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8D 54 24 ?? 48 8D 8D ?? ?? 
            ?? ?? FF 15 ?? ?? ?? ?? 48 8B D8 48 83 F8 ?? 0F 84 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 
            48 8D 4C 24 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4C 24 ?? FF 
            15 ?? ?? ?? ?? 85 C0 74 ?? 48 8D 44 24 ?? 4C 8B CF 4C 8D 05 ?? ?? ?? ?? 48 89 44 24 
            ?? BA ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? F6 44 24 ?? ?? 48 8D 8D ?? 
            ?? ?? ?? 74 ?? 48 8D 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? EB ?? FF 15 ?? ?? ?? ?? 48 8D 54 24 ?? 48 8B CB FF 15 ?? ?? ?? ?? 85 C0 0F 85 
            ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? 48 8B CF FF 15 ?? ?? ?? ?? 48 8B 8D ?? ?? ?? 
            ?? 48 33 CC E8 ?? ?? ?? ?? 4C 8D 9C 24 ?? ?? ?? ?? 49 8B 5B ?? 49 8B 7B ?? 49 8B E3 
            5D C3 
        }

        $encrypt_files_p1 = {
            FF 15 ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 63 C8 48 8D 85 ?? ?? ?? 
            ?? 48 8D 04 48 48 83 C0 ?? 66 83 38 ?? 75 ?? 45 33 FF 4C 8D 05 ?? ?? ?? ?? 66 44 89 
            38 45 33 C9 48 83 C0 ?? 4C 89 7C 24 ?? 48 89 05 ?? ?? ?? ?? 33 D2 48 8D 05 ?? ?? ?? 
            ?? 44 89 7C 24 ?? 33 C9 48 89 05 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 D2 45 8D 47 ?? 33 
            C9 FF 15 ?? ?? ?? ?? 48 8B F0 48 85 C0 74 ?? 48 8B 1D ?? ?? ?? ?? 48 81 C3 ?? ?? ?? 
            ?? EB ?? 48 8B CB FF 15 ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? 48 8B D3 48 8B CE 44 8B F0 FF 
            15 ?? ?? ?? ?? 48 8B F8 48 85 C0 74 ?? 4C 8D 85 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 8B C8 
            FF 15 ?? ?? ?? ?? 48 8B CF FF 15 ?? ?? ?? ?? 41 8D 46 ?? 48 63 C8 48 8D 1C 4B 66 44 
            39 3B 75 ?? 48 8B CE FF 15 ?? ?? ?? ?? 33 D2 8D 4A ?? FF 15 ?? ?? ?? ?? 48 8B F8 48 
            83 F8 ?? 0F 84 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? EB ?? 48 8B 1D ?? ?? ?? ?? 48 81 
            C3 ?? ?? ?? ?? EB ?? 48 8B CB FF 15 ?? ?? ?? ?? 48 8B D3 48 8D 4C 24 ?? 44 8B F0 FF 
            15 ?? ?? ?? ?? 85 C0 75 ?? 44 8B 44 24 ?? 8D 48 ?? 33 D2 FF 15 ?? ?? ?? ?? 48 8B F0 
            48 83 F8 ?? 74 ?? 33 D2 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B CE FF 15 ?? ?? ?? ?? 41 8D 
            46 ?? 48 63 C8 48 8D 1C 4B 66 44 39 3B 75 ?? 48 8D 54 24 ?? 48 8B CF FF 15 ?? ?? ?? 
            ?? 85 C0 75 ?? 48 8B CF FF 15 ?? ?? ?? ?? 33 D2 48 8D 8D ?? ?? ?? ?? 41 B8 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 D2 48 8D 35 ?? ?? ?? ?? 48
        }

        $encrypt_files_p2 = {
            8D 8D ?? ?? ?? ?? 48 89 B5 ?? ?? ?? ?? 44 8D 42 ?? E8 ?? ?? ?? ?? 4C 8B 05 ?? ?? ?? 
            ?? 48 8D 8D ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? BB ?? ?? ?? ?? 4C 89 BD 
            ?? ?? ?? ?? 44 8B CB C7 44 24 ?? ?? ?? ?? ?? 45 33 C0 48 8D 8D ?? ?? ?? ?? 33 D2 FF 
            15 ?? ?? ?? ?? 85 C0 75 ?? FF 15 ?? ?? ?? ?? 3D ?? ?? ?? ?? 75 ?? 48 8D 44 24 ?? 45 
            33 C9 45 33 C0 48 89 44 24 ?? 8D 53 ?? 33 C9 FF 15 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 
            48 8D 4C 24 ?? FF 15 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? EB ?? FF 15 ?? ?? ?? 
            ?? 3D ?? ?? ?? ?? 75 ?? 44 8B CB C7 44 24 ?? ?? ?? ?? ?? 45 33 C0 48 8D 8D ?? ?? ?? 
            ?? 33 D2 FF 15 ?? ?? ?? ?? 48 8B BD ?? ?? ?? ?? 48 85 FF 0F 84 ?? ?? ?? ?? 48 8B 0D 
            ?? ?? ?? ?? 41 8B DF 48 81 C1 ?? ?? ?? ?? 45 8B F7 FF 15 ?? ?? ?? ?? 85 C0 7E ?? 49 
            8B F7 48 8B 05 ?? ?? ?? ?? 4C 8D 05 ?? ?? ?? ?? BA ?? ?? ?? ?? 0F BE 8C 06 ?? ?? ?? 
            ?? 44 0F BE 8C 06 ?? ?? ?? ?? 89 4C 24 ?? 48 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 D2 
            48 8D 8D ?? ?? ?? ?? 44 8D 42 ?? E8 ?? ?? ?? ?? 8B CB 48 8D 76 ?? FF C3 41 83 C6 ?? 
            88 84 0D ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 81 C1 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 44 
        }

        $encrypt_files_p3 = {
            3B F0 7C ?? 48 8D 35 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 45 33 C9 48 89 44 24 ?? 48 8D 
            95 ?? ?? ?? ?? 44 8B C3 44 89 7C 24 ?? 48 8B CF FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? 
            ?? ?? 48 8B 1D ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 4C 8B C3 E8 ?? 
            ?? ?? ?? 48 8B 8D ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 45 33 C9 C7 44 24 ?? ?? ?? ?? ?? 
            48 89 44 24 ?? 33 D2 48 8D 85 ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 48 89 44 24 ?? 45 8D 41 
            ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 41 8B DF 44 39 BD ?? ?? ?? ?? 76 ?? 8B C3 4C 8D 05 
            ?? ?? ?? ?? BA ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? 44 0F B6 8C 05 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF C3 3B 9D ?? ?? 
            ?? ?? 72 ?? 48 8B 8D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 D2 48 8B CF FF 15 ?? ?? ?? ?? 
            48 8B 05 ?? ?? ?? ?? 4C 8D 8D ?? ?? ?? ?? 48 83 C0 ?? 4C 8D 05 ?? ?? ?? ?? BA ?? ?? 
            ?? ?? 48 89 44 24 ?? 48 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F 6F 05 ?? ?? 06 00 48 
            8D 95 ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? 66 44 89 BD ?? ?? 00 00 F3 0F 7F 85 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            48 8D 8D ?? ?? ?? ?? 48 89 B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 48 8B 8D ?? ?? ?? ?? 
            48 33 CC E8 ?? ?? ?? ?? 4C 8D 9C 24 ?? ?? ?? ?? 49 8B 5B ?? 49 8B 73 ?? 49 8B 7B ?? 
            49 8B E3 41 5F 41 5E 5D C3 
        }

    condition:
        uint16(0) == 0x5A4D and $search_files and (all of ($encrypt_files_p*))
}