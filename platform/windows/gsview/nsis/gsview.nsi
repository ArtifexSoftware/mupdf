;  Copyright (C) 2015 Artifex Software, Inc.
;  All Rights Reserved.
;
;  This software is provided AS-IS with no warranty, either express or
;  implied.
;
;  This software is distributed under license and may not be copied,
;  modified or distributed except as expressly authorized under the terms
;  of the license contained in the file LICENSE in this distribution.
;  
;  Refer to licensing information at http://www.artifex.com or contact
;  Artifex Software, Inc.,  7 Mt. Lassen Drive - Suite A-134, San Rafael,
;  CA  94903, U.S.A., +1(415)492-9861, for further information.
;

; This script should be compiled with :
;     makensis -NOCD nsis/gsview.nsi
 
!ifndef TARGET
!define TARGET gsview_setup
!endif

!ifndef VERSION
!define VERSION 6.0
!endif

!ifndef PRODUCT_NAME
!define PRODUCT_NAME gsview
!endif

SetCompressor /SOLID /FINAL lzma
XPStyle on
CRCCheck on

!include "nsDialogs.nsh"
; modern user interface
!include "MUI2.nsh"
; for logic marcos that occur at run time.  Not compile time
!include "LogicLib.nsh"
; for detecting if running on x64 machine.
!include "x64.nsh"

; Macros for file association.
; to make sure that we update the proper locations (user vs root for example
; as well as changes needed for Windows 8.x)
!macro APP_ASSOCIATE EXT FILECLASS DESCRIPTION ICON COMMANDTEXT COMMAND TOAST SETDEFAULT
  ; Backup the previously associated file class

    ${If} ${SETDEFAULT} == "1"
        ;DetailPrint "ReadRegStr HKCU Software\Classes\  $R0"
        ReadRegStr $R0 HKCU "Software\Classes\.${EXT}" ""

        ;DetailPrint "WriteRegStr of backup in HKCU"
        WriteRegStr HKCU "Software\Classes\.${EXT}" "${FILECLASS}_backup" "$R0"

        ;DetailPrint "WriteRegStr of fileclass in HKCU"
        WriteRegStr HKCU "Software\Classes\.${EXT}" "" "${FILECLASS}"

      ; If this key is present (as it in windows 8) then we need to do this to get the
      ; proper file type icon rather than just the application icon for the file type.
        ${If} ${TOAST} == '1'
            WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts\" "${FILECLASS}_" 0
        ${EndIf}
    ${EndIf}

  ; The icon mapping should not go in HKCR but in HKLM per MS best practices
    WriteRegStr HKLM "Software\Classes\${FILECLASS}" "" `${DESCRIPTION}`
    WriteRegStr HKLM "Software\Classes\${FILECLASS}\DefaultIcon" "" `${ICON}`
    WriteRegStr HKLM "Software\Classes\${FILECLASS}\shell" "" "open"
    WriteRegStr HKLM "Software\Classes\${FILECLASS}\shell\open" "" `${COMMANDTEXT}`
    WriteRegStr HKLM "Software\Classes\${FILECLASS}\shell\open\command" "" `${COMMAND}`
!macroend

!macro APP_UNASSOCIATE EXT FILECLASS TOAST
  ; Get the previously associated file class
    ReadRegStr $R0 HKCU "Software\Classes\.${EXT}" `${FILECLASS}_backup`
    WriteRegStr HKCU "Software\Classes\.${EXT}" "" "$R0"

  ; Delete backup value
    DeleteRegValue HKCU "Software\Classes\.${EXT}" "${FILECLASS}_backup"

  ; If this key is present (as it in windows 8) then attempt to clean up. System
  ; seems to add in other entries here that I did not do depending upon what the
  ; type of associations the user has done.
    ${If} ${TOAST} == '1'
        DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts\" "${FILECLASS}_"
    ${EndIf}

  ; Remove icon mapping
    DeleteRegKey HKLM `Software\Classes\${FILECLASS}`
!macroend

; defines for use with SHChangeNotify
!ifdef SHCNE_ASSOCCHANGED
!undef SHCNE_ASSOCCHANGED
!endif
!define SHCNE_ASSOCCHANGED 0x08000000
!ifdef SHCNF_FLUSH
!undef SHCNF_FLUSH
!endif
!define SHCNF_FLUSH        0x1000

!macro UPDATEFILEASSOC
      System::Call "shell32::SHChangeNotify(i,i,i,i) (${SHCNE_ASSOCCHANGED}, ${SHCNF_FLUSH}, 0, 0)"
!macroend

!define MUI_FINISHPAGE_RUN "$INSTDIR\bin\gsview.exe"
!define MUI_FINISHPAGE_LINK          "Visit the Ghostscript web site"
!define MUI_FINISHPAGE_LINK_LOCATION http://www.ghostscript.com/

; Order of page appearance
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
Page custom fnc_association_Show fnc_association_Done
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

!searchparse /ignorecase /noerrors "${TARGET}" w WINTYPE
!echo "Building ${WINTYPE}-bit installer"

Name "gsview"
OutFile "${TARGET}_${VERSION}.exe"
Icon Resources\gsview_app.ico
UninstallIcon Resources\gsview_app.ico

; We need to have then run this as an adminstrator.  Otherwise there are
; issues with the icons for the various file types and getting the "Open With.."
; items populated

RequestExecutionLevel admin

; Some default compiler settings (uncomment and change at will):
; SetCompress auto ; (can be off or force)
; SetDatablockOptimize on ; (can be off)
; CRCCheck on ; (can be off)
; AutoCloseWindow false ; (can be true for the window go away automatically at end)
; ShowInstDetails hide ; (can be show to have them shown, or nevershow to disable)
; SetDateSave off ; (can be on to have files restored to their orginal date)

BrandingText "Artifex Software Inc."
LicenseText "You must agree to this license before installing."
LicenseData "LICENSE"

; It is OK to use $PROGRAMFILES64 on x86
; you can use $PROGRAMFILES64 for all platforms.  It will go to default
InstallDir "$PROGRAMFILES64\Artifex Software\gsview${VERSION}"

DirText "Select the directory to install gsview in:"

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; 
; Association dialog: Partially created with CoolSoft NSIS Dialog Designer.
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

Var hCtl_association
Var hCtl_association_jpg
Var hCtl_association_png
Var hCtl_association_xps
Var hCtl_association_oxps
Var hCtl_association_eps
Var hCtl_association_ps
Var hCtl_association_cbz
Var hCtl_association_pdf
Var jpg
Var png
Var xps
Var oxps
Var eps
Var ps
Var cbz
Var pdf

; dialog create function
Function fnc_association_Create
  
  ; === association (type: Dialog) ===
  nsDialogs::Create 1018
  Pop $hCtl_association
  ${If} $hCtl_association == error
    Abort
  ${EndIf}
  !insertmacro MUI_HEADER_TEXT "File Type Associations" "Select.."

  ; === jpg (type: Checkbox) ===
  ${NSD_CreateCheckbox} 192.2u 57.85u 78.99u 23.38u "jpg"
  Pop $hCtl_association_jpg
  ${NSD_Check} $hCtl_association_jpg
  
  ; === png (type: Checkbox) ===
  ${NSD_CreateCheckbox} 192.2u 43.69u 68.46u 14.77u "png"
  Pop $hCtl_association_png
  ${NSD_Check} $hCtl_association_png
  
  ; === xps (type: Checkbox) ===
  ${NSD_CreateCheckbox} 123.09u 45.54u 70.43u 11.69u "xps"
  Pop $hCtl_association_xps
  ${NSD_Check} $hCtl_association_xps
  
  ; === oxps (type: Checkbox) ===
  ${NSD_CreateCheckbox} 123.09u 57.85u 73.06u 23.38u "oxps"
  Pop $hCtl_association_oxps
  ${NSD_Check} $hCtl_association_oxps
  
  ; === eps (type: Checkbox) ===
  ${NSD_CreateCheckbox} 50.68u 80.62u 68.46u 14.77u "eps"
  Pop $hCtl_association_eps
  ${NSD_Check} $hCtl_association_eps
  
  ; === ps (type: Checkbox) ===
  ${NSD_CreateCheckbox} 50.68u 62.15u 62.53u 14.77u "ps"
  Pop $hCtl_association_ps
  ${NSD_Check} $hCtl_association_ps
  
  ; === cbz (type: Checkbox) ===
  ${NSD_CreateCheckbox} 192.2u 80.62u 68.46u 14.77u "cbz"
  Pop $hCtl_association_cbz
  ${NSD_Check} $hCtl_association_cbz
  
  ; === pdf (type: Checkbox) ===
  ${NSD_CreateCheckbox} 50.68u 43.69u 68.46u 14.77u "pdf"
  Pop $hCtl_association_pdf
  ${NSD_Check} $hCtl_association_pdf
  
FunctionEnd

; Association dialog show function
Function fnc_association_Show
    Call fnc_association_Create
    nsDialogs::Show $hCtl_association
FunctionEnd

; Association dialog done function
Function fnc_association_Done
    ${NSD_GetState} $hCtl_association_jpg $0
    ${If} $0 <> 0
        StrCpy $jpg "1"
    ${Else}
        StrCpy $jpg "0"
    ${EndIf}

    ${NSD_GetState} $hCtl_association_xps $0
    ${If} $0 <> 0
        StrCpy $xps "1"
    ${Else}
        StrCpy $xps "0"
    ${EndIf}
    
    ${NSD_GetState} $hCtl_association_oxps $0
    ${If} $0 <> 0
        StrCpy $oxps "1"
    ${Else}
        StrCpy $oxps "0"
    ${EndIf}

    ${NSD_GetState} $hCtl_association_png $0
    ${If} $0 <> 0
        StrCpy $png "1"
    ${Else}
        StrCpy $png "0"
    ${EndIf}

    ${NSD_GetState} $hCtl_association_eps $0
    ${If} $0 <> 0
        StrCpy $eps "1"
    ${Else}
        StrCpy $eps "0"
    ${EndIf}

    ${NSD_GetState} $hCtl_association_ps $0
    ${If} $0 <> 0
        StrCpy $ps "1"
    ${Else}
        StrCpy $ps "0"
    ${EndIf}

    ${NSD_GetState} $hCtl_association_cbz $0
    ${If} $0 <> 0
        StrCpy $cbz "1"
    ${Else}
        StrCpy $cbz "0"
    ${EndIf}

    ${NSD_GetState} $hCtl_association_pdf $0
    ${If} $0 <> 0
        StrCpy $pdf "1"
    ${Else}
        StrCpy $pdf "0"
    ${EndIf}

FunctionEnd

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; 
; Main Install Section 
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

Section "" ; (default section)

  ; First check if we have the proper .net installed
    Call CheckAndDownloadDotNet45

    SetOutPath "$INSTDIR"
    CreateDirectory "$INSTDIR\bin"
    CreateDirectory "$INSTDIR\resources"
  ; add files / whatever that need to be installed here.
    ${If} ${RunningX64}
        File /oname=bin\gsprint64.dll .\bin\Release\gsprint64.dll
        File /oname=bin\mupdfnet64.dll .\bin\Release\mupdfnet64.dll
        File /oname=bin\gsdll64.dll .\gslib\gsdll64.dll
    ${Else}
        File /oname=bin\gsprint32.dll .\bin\Release\gsprint32.dll
        File /oname=bin\mupdfnet32.dll .\bin\Release\mupdfnet32.dll
        File /oname=bin\gsdll32.dll .\gslib\gsdll32.dll
    ${EndIf}
    File /oname=bin\gsview.exe .\bin\Release\gsview.exe
    File /oname=resources\pageCBZ.ico .\Resources\pageCBZ.ico
    File /oname=resources\pageEPS.ico .\Resources\pageEPS.ico
    File /oname=resources\pagePS.ico .\Resources\pagePS.ico
    File /oname=resources\pagePDF.ico .\Resources\pagePDF.ico
    File /oname=resources\pageXPS.ico .\Resources\pageXPS.ico
    File /oname=resources\pageOXPS.ico .\Resources\pageOXPS.ico
    File /oname=resources\pagePNG.ico .\Resources\pagePNG.ico
    File /oname=resources\pageJPG.ico .\Resources\pageJPG.ico

    ${If} ${RunningX64}
      SetRegView 64
    ${EndIf}
    WriteRegStr HKEY_LOCAL_MACHINE "Software\Artifex Software\gsview\${VERSION}" "" "$INSTDIR"
    WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\gsview ${VERSION}" "DisplayName" "gsview"
    WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\gsview ${VERSION}" "UninstallString" '"$INSTDIR\uninstgsview.exe"'
    WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\gsview ${VERSION}" "Publisher" "Artifex Software Inc."
    WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\gsview ${VERSION}" "HelpLink" "http://www.ghostscript.com/"
    WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\gsview ${VERSION}" "URLInfoAbout" "http://www.ghostscript.com/"
    WriteRegStr HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\gsview ${VERSION}" "DisplayVersion" "${VERSION}"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\gsview ${VERSION}" "NoRepair" "1"

  ; Check if Toast directory is present before doing the associations
    StrCpy $0 0
    StrCpy $2 0
    ${Do}
      EnumRegKey $1 HKCU Software\Microsoft\Windows\CurrentVersion $0
      ${If} $1 == 'ApplicationAssociationToasts'
        StrCpy $2 1
        StrCpy $1 ""  ; End it now as we have found the entry
      ${EndIf}
      IntOp $0 $0 + 1
    ${LoopUntil} $1 == ""

  ; The file associations
    !insertmacro APP_ASSOCIATE "pdf" "gsview.pdf" "PDF Document" "$INSTDIR\resources\pagePDF.ico" "Open" "$INSTDIR\bin\gsview.exe $\"%1$\"" $2 $pdf
    !insertmacro APP_ASSOCIATE "ps" "gsview.ps" "Postscript Document" "$INSTDIR\resources\pagePS.ico" "Open" "$INSTDIR\bin\gsview.exe $\"%1$\"" $2 $ps
    !insertmacro APP_ASSOCIATE "xps" "gsview.xps" "XPS Document" "$INSTDIR\resources\pageXPS.ico" "Open" "$INSTDIR\bin\gsview.exe $\"%1$\"" $2 $xps
    !insertmacro APP_ASSOCIATE "oxps" "gsview.oxps" "Open XPS Document" "$INSTDIR\resources\pageOXPS.ico" "Open" "$INSTDIR\bin\gsview.exe $\"%1$\"" $2 $oxps
    !insertmacro APP_ASSOCIATE "cbz" "gsview.cbz" "CBZ Document" "$INSTDIR\resources\pageCBZ.ico" "Open" "$INSTDIR\bin\gsview.exe $\"%1$\"" $2 $cbz
    !insertmacro APP_ASSOCIATE "jpg" "gsview.jpg" "JPG Image" "$INSTDIR\resources\pageJPG.ico" "Open" "$INSTDIR\bin\gsview.exe $\"%1$\"" $2 $jpg
    !insertmacro APP_ASSOCIATE "png" "gsview.png" "PNG Image" "$INSTDIR\resources\pagePNG.ico" "Open" "$INSTDIR\bin\gsview.exe $\"%1$\"" $2 $png
    !insertmacro APP_ASSOCIATE "eps" "gsview.eps" "Encapsulated Postscript" "$INSTDIR\resources\pageEPS.ico" "Open" "$INSTDIR\bin\gsview.exe $\"%1$\"" $2 $eps
    !insertmacro UPDATEFILEASSOC

  ; write out uninstaller
    WriteUninstaller "$INSTDIR\uninstgsview.exe"
SectionEnd ; end of default section

Function .onInstSuccess
    SetShellVarContext all
    CreateDirectory "$SMPROGRAMS\gsview"
    CreateShortCut "$SMPROGRAMS\gsview\gsview ${VERSION}.LNK" "$INSTDIR\bin\gsview.exe"
    CreateShortCut "$SMPROGRAMS\gsview\Uninstall gsview ${VERSION}.LNK" "$INSTDIR\uninstgsview.exe"
FunctionEnd

Function .onInit
    ; Again, check that we they are doing a run as administrator
    UserInfo::GetAccountType
    pop $0
    ${If} $0 != "admin" ;Require admin rights
        MessageBox mb_iconstop "Administrator rights required!"
        SetErrorLevel 740 ;ERROR_ELEVATION_REQUIRED
        Quit
    ${EndIf}

    System::Call 'kernel32::CreateMutexA(i 0, i 0, t "GhostscriptInstaller") i .r1 ?e'
    Pop $R0
    StrCmp $R0 0 +3
    MessageBox MB_OK "The gsview installer is already running." /SD IDOK
    Abort
FunctionEnd

Function Un.onInit
    ${If} ${RunningX64}
        SetRegView 64
    ${EndIf}
FunctionEnd

; begin uninstall settings/section
UninstallText "This will uninstall gsview from your system"

Section Uninstall
  ; add delete commands to delete whatever files/registry keys/etc you installed here.
    SetShellVarContext all
    Delete   "$SMPROGRAMS\gsview\gsview ${VERSION}.LNK"
    Delete   "$SMPROGRAMS\gsview\Uninstall gsview ${VERSION}.LNK"
    RMDir    "$SMPROGRAMS\gsview"
    Delete   "$INSTDIR\uninstgsview.exe"

    ${If} ${RunningX64}
        SetRegView 64
    ${EndIf}
    ; Check if Toast directory is present before doing the unassociations
    StrCpy $0 0
    StrCpy $2 0
    ${Do}
      EnumRegKey $1 HKCU Software\Microsoft\Windows\CurrentVersion $0
      ${If} $1 == 'ApplicationAssociationToasts'
        StrCpy $2 1
        StrCpy $1 ""
      ${EndIf}
      IntOp $0 $0 + 1
    ${LoopUntil} $1 == ""

    !insertmacro APP_UNASSOCIATE "pdf" "gsview.pdf" $2
    !insertmacro APP_UNASSOCIATE "ps" "gsview.ps" $2
    !insertmacro APP_UNASSOCIATE "xps" "gsview.xps" $2
    !insertmacro APP_UNASSOCIATE "oxps" "gsview.oxps" $2
    !insertmacro APP_UNASSOCIATE "cbz" "gsview.cbz" $2
    !insertmacro APP_UNASSOCIATE "jpg" "gsview.jpg" $2
    !insertmacro APP_UNASSOCIATE "png" "gsview.png" $2

    DeleteRegKey HKEY_CURRENT_USER "Software\Artifex Software\GSview ${Version}"

    DeleteRegKey HKEY_LOCAL_MACHINE "SOFTWARE\Artifex Software\gsview\${VERSION}"
    DeleteRegKey HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\gsview ${VERSION}"
    DeleteRegKey HKEY_LOCAL_MACHINE "Software\gsview\${VERSION}"
    RMDir /r "$INSTDIR\doc"
    Delete   "$INSTDIR\bin\gsprint${WINTYPE}.dll"
    Delete   "$INSTDIR\bin\mupdfnet{WINTYPE}.dll"
    Delete   "$INSTDIR\bin\gsdll${WINTYPE}.dll"
    Delete   "$INSTDIR\bin\gsview.exe"
    Delete   "$INSTDIR\resources\pageCBZ.ico"
    Delete   "$INSTDIR\resources\pageEPS.ico"
    Delete   "$INSTDIR\resources\pageJPG.ico"
    Delete   "$INSTDIR\resources\pageOXPS.ico"
    Delete   "$INSTDIR\resources\pagePDF.ico"
    Delete   "$INSTDIR\resources\pagePS.ico"
    Delete   "$INSTDIR\resources\pageXPS.ico"
    Delete   "$INSTDIR\resources\pagePNG.ico"
    RMDir    "$INSTDIR\resources"
    RMDir    "$INSTDIR\bin"
    RMDir    "$INSTDIR"
SectionEnd ; end of uninstall section

; From http://nsis.sourceforge.net/Download_and_Install_dotNET_45
Function CheckAndDownloadDotNet45
    # Let's see if the user has the .NET Framework 4.5 installed on their system or not
    # Remember: you need Vista SP2 or 7 SP1.  It is built in to Windows 8, and not needed
    # In case you're wondering, running this code on Windows 8 will correctly return is_equal
    # or is_greater (maybe Microsoft releases .NET 4.5 SP1 for example)
 
    # Set up our Variables
    Var /GLOBAL dotNET45IsThere
    Var /GLOBAL dotNET_CMD_LINE
    Var /GLOBAL EXIT_CODE
 
    # We are reading a version release DWORD that Microsoft says is the documented
    # way to determine if .NET Framework 4.5 is installed
    ReadRegDWORD $dotNET45IsThere HKLM "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" "Release"
    IntCmp $dotNET45IsThere 378389 is_equal is_less is_greater
 
    is_equal:
        Goto done_compare_not_needed
    is_greater:
        # Useful if, for example, Microsoft releases .NET 4.5 SP1
        # We want to be able to simply skip install since it's not
        # needed on this system
        Goto done_compare_not_needed
    is_less:
        Goto done_compare_needed
 
    done_compare_needed:
        #.NET Framework 4.5 install is *NEEDED*
 
        # Microsoft Download Center EXE:
        # Web Bootstrapper: http://go.microsoft.com/fwlink/?LinkId=225704
        # Full Download: http://go.microsoft.com/fwlink/?LinkId=225702
 
        # Setup looks for components\dotNET45Full.exe relative to the install EXE location
        # This allows the installer to be placed on a USB stick (for computers without internet connections)
        # If the .NET Framework 4.5 installer is *NOT* found, Setup will connect to Microsoft's website
        # and download it for you
 
        # Reboot Required with these Exit Codes:
        # 1641 or 3010
 
        # Command Line Switches:
        # /showrmui /passive /norestart
 
        # Silent Command Line Switches:
        # /q /norestart
 
        # Let's see if the user is doing a Silent install or not
        IfSilent is_quiet is_not_quiet
 
        is_quiet:
            StrCpy $dotNET_CMD_LINE "/q /norestart"
            Goto LookForLocalFile
        is_not_quiet:
            StrCpy $dotNET_CMD_LINE "/showrmui /passive /norestart"
            Goto LookForLocalFile
 
        LookForLocalFile:
            # Let's see if the user stored the Full Installer
            IfFileExists "$EXEPATH\components\dotNET45Full.exe" do_local_install do_network_install
 
            do_local_install:
                # .NET Framework found on the local disk.  Use this copy 
                ExecWait '"$EXEPATH\components\dotNET45Full.exe" $dotNET_CMD_LINE' $EXIT_CODE
                Goto is_reboot_requested
            # Now, let's Download the .NET

            do_network_install:
                Var /GLOBAL dotNetDidDownload
                NSISdl::download "http://go.microsoft.com/fwlink/?LinkId=225704" "$TEMP\dotNET45Web.exe" $dotNetDidDownload
                StrCmp $dotNetDidDownload success fail

                success:
                    ExecWait '"$TEMP\dotNET45Web.exe" $dotNET_CMD_LINE' $EXIT_CODE
                    Goto is_reboot_requested
 
                fail:
                    MessageBox MB_OK|MB_ICONEXCLAMATION "Unable to download .NET Framework. ${PRODUCT_NAME} will be installed, but will not function without the Framework!"
                    Goto done_dotNET_function
 
                # $EXIT_CODE contains the return codes.  1641 and 3010 means a Reboot has been requested
                is_reboot_requested:
                    ${If} $EXIT_CODE = 1641
                    ${OrIf} $EXIT_CODE = 3010
                        SetRebootFlag true
                    ${EndIf}
 
    done_compare_not_needed:
        # Done dotNET Install
        Goto done_dotNET_function
 
    #exit the function
    done_dotNET_function:
 
    FunctionEnd
; eof
