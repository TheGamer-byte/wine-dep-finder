import os
import pefile

def analyze_windows_program(file_path):
    """
    Analyze a Windows executable file and list its dependencies.
    """
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        return
    try:
        pe = pefile.PE(file_path)
        print(f"Analyzing: {file_path}")
        print("Imported DLLs:")
        imported_dlls = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            imported_dlls.append(dll_name)
            print(f" - {dll_name}")
        pe.close()
        # Provide Winetricks recommendations
        recommend_winetricks_components(imported_dlls)
    except pefile.PEFormatError:
        print("Error: The file is not a valid PE (Portable Executable) file.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
def recommend_winetricks_components(imported_dlls):
    """
    Recommend Winetricks DLLs or components based on imported DLLs.
    """
    winetricks_mapping = {
        "d3dx9_43.dll": "d3dx9",
        "d3dx10_43.dll": "d3dx10",
        "d3dx11_43.dll": "d3dx11",
        "d3dcompiler_43.dll": "d3dcompiler_43",
        "d3dcompiler_47.dll": "d3dcompiler_47",
        "msvcr100.dll": "vcrun2010",
        "msvcr110.dll": "vcrun2012",
        "msvcr120.dll": "vcrun2013",
        "msvcr140.dll": "vcrun2015",
        "msvcr150.dll": "vcrun2022",
        "msvcp100.dll": "vcrun2010",
        "msvcp110.dll": "vcrun2012",
        "msvcp120.dll": "vcrun2013",
        "msvcp140.dll": "vcrun2015",
        "msvcp150.dll": "vcrun2022",
        "xinput1_3.dll": "xinput",
        "xinput1_4.dll": "xinput",
        "xinput9_1_0.dll": "xinput",
        "dxgi.dll": "dxvk",
        "d3d11.dll": "dxvk",
        "dinput8.dll": "dinput",
        "vulkan-1.dll": "vulkan",
        "ucrtbase.dll": "vcrun2019",
        "api-ms-win-crt-runtime-l1-1-0.dll": "vcrun2015",
        "api-ms-win-crt-stdio-l1-1-0.dll": "vcrun2015",
        "api-ms-win-crt-math-l1-1-0.dll": "vcrun2015",
        "api-ms-win-crt-convert-l1-1-0.dll": "vcrun2015",
        "api-ms-win-crt-filesystem-l1-1-0.dll": "vcrun2015",
        "api-ms-win-crt-environment-l1-1-0.dll": "vcrun2015",
        "api-ms-win-crt-time-l1-1-0.dll": "vcrun2015",
        "api-ms-win-crt-string-l1-1-0.dll": "vcrun2015",
        "api-ms-win-crt-heap-l1-1-0.dll": "vcrun2015",
        "api-ms-win-crt-locale-l1-1-0.dll": "vcrun2015",
        "api-ms-win-crt-utility-l1-1-0.dll": "vcrun2015",
        "mfplat.dll": "mf",
        "mf.dll": "mf",
        "mfreadwrite.dll": "mf",
        "msmpeg2vdec.dll": "mf",
        "evr.dll": "mf",
        "mfcore.dll": "mf",
        "mfplay.dll": "mf",
        "mfsvr.dll": "mf",
        "mfperfhelper.dll": "mf",
    }

    print("\nRecommended Winetricks components:")
    recommended = set()
    for dll in imported_dlls:
        if dll.lower() in winetricks_mapping:
            recommended.add(winetricks_mapping[dll.lower()])
    if recommended:
        for component in recommended:
            print(f" - {component}")
    else:
        print("No specific Winetricks components recommended for the imported DLLs.")
if __name__ == "__main__":
    file_path = input("Enter the path to the Windows executable file: ").strip()
    analyze_windows_program(file_path)