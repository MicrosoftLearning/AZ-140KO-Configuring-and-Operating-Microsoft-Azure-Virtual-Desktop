---
lab:
    title: '랩: Azure Virtual Desktop 프로필 구현 및 관리(Azure AD DS)'
    module: '모듈 4: 사용자 환경 및 앱 관리'
---

# 랩 - Azure Virtual Desktop 프로필 구현 및 관리(Azure AD DS)
# 학생 랩 매뉴얼

## 랩 종속성

- Azure 구독
- Azure 구독과 연결된 Azure AD 테넌트의 전역 관리자 역할, 그리고 Azure 구독의 Owner 또는 Contributor 역할이 할당되어 있는 Microsoft 계정 또는 Azure AD 계정
- **Azure Virtual Desktop 소개(Azure AD DS)** 랩에서 프로비전한 Azure Virtual Deskktop 환경

## 예상 시간

30분

## 랩 시나리오

Azure Active Directory Domain Services(Azure AD DS) 환경에서 Azure Virtual Desktop 프로필 관리를 구현해야 합니다.

## 목표
  
이 랩을 완료하면 다음을 수행할 수 있습니다.

- Azure AD DS 환경에서 Azure Virtual Desktop용 프로필 컨테이너를 저장하도록 Azure Files 구성
- Azure AD DS 환경에서 Azure Virtual Desktop용 FSLogix 기반 프로필 구현

## 랩 파일

- 없음

## 지침

### 연습 1: Azure Virtual Desktop용 FSLogix 기반 프로필 구현

이 연습의 주요 작업은 다음과 같습니다.

1. Azure Virtual Desktop 세션 호스트 VM에서 로컬 관리자 그룹 구성
1. Azure Virtual Desktop 세션 호스트 VM에서 FSLogix 기반 프로필 구성
1. Azure Virtual Desktop을 사용하여 FSLogix 기반 프로필 테스트
1. Azure 랩 리소스 삭제

#### 작업 1: Azure Virtual Desktop 세션 호스트 VM에서 로컬 관리자 그룹 구성

1. 랩 컴퓨터에서 웹 브라우저를 시작하여 [Azure Portal](https://portal.azure.com)로 이동하고 이 랩에서 사용할 구독에서 Owner 역할을 가진 사용자 계정의 자격 증명을 제공하여 로그인합니다.
1. 랩 컴퓨터에 표시된 Azure Portal에서 **가상 머신**을 검색하여 선택하고 **가상 머신** 블레이드에서 **az140-cl-vm11a** 항목을 선택합니다. 그러면 **az140-cl-vm11a** 블레이드가 열립니다.
1. **az140-cl-vm11a** 블레이드에서 **연결**을 선택하고 드롭다운 메뉴에서 **Bastion**을 선택합니다. 그런 다음 **az140-cl-vm11a \| 연결** 블레이드의 **Bastion** 탭에서 **Bastion 사용**을 선택합니다.
1. 메시지가 표시되면 다음 자격 증명을 제공하고 **연결**을 선택합니다.

   |설정|값|
   |---|---|
   |사용자 이름|**Student@adatum.com**|
   |암호|**Pa55w.rd1234**|

1. **az140-cl-vm11a**에 연결된 원격 데스크톱 세션 내의 시작 메뉴에서 **Windows 관리 도구** 폴더로 이동하여 해당 폴더를 확장하고 **Active Directory 사용자 및 컴퓨터**를 선택합니다.
1. **Active Directory 사용자 및 컴퓨터** 콘솔에서 도메인 노드를 마우스 오른쪽 단추로 클릭하고 **새로 만들기** > **조직 구성 단위**를 선택합니다. 그런 다음 **새 개체 - 조직 구성 단위** 대화 상자의 **이름** 텍스트 상자에 **ADDC 사용자**를 입력하고 **확인**을 선택합니다.
1. **Active Directory 사용자 및 컴퓨터** 콘솔에서 **ADDC 사용자**를 마우스 오른쪽 단추로 클릭하고 **새로 만들기** > **그룹**을 선택합니다. 그런 다음 **새 개체 - 그룹** 대화 상자에서 다음 설정을 지정하고 **OK**을 선택합니다.

   |설정|값|
   |---|---|
   |그룹 이름|**Local Admins**|
   |그룹 이름(Windows 2000 이전 버전)|**Local Admins**|
   |그룹 범위|**전역**|
   |그룹 유형|**보안**|

1. **Active Directory 사용자 및 컴퓨터** 콘솔에 **Local Admins** 그룹의 속성을 표시하고 **구성원** 탭으로 전환하여 **추가**를 선택합니다. 그런 다음 **사용자, 연락처, 컴퓨터, 서비스 계정 또는 그룹 선택** 대화 상자의 **선택할 개체 이름을 입력하십시오**. 에 **aadadmin1**을 입력하고 **확인**을 선택합니다.
1. **az140-cl-vm11a**에 연결된 원격 데스크톱 세션 내의 시작 메뉴에서 **Windows 관리 도구** 폴더로 이동하여 해당 폴더를 확장하고 **그룹 정책 관리**를 선택합니다.
1. **그룹 정책 관리** 콘솔에서 **AADDC 컴퓨터** OU로 이동하여 **AADDC 컴퓨터 GPO** 아이콘을 마우스 오른쪽 단추로 클릭한 후 **편집**을 선택합니다.
1. **그룹 정책 관리 편집기** 콘솔에서 **컴퓨터 구성**, **정책**, **Windows 설정**, **보안 설정**을 확장하고 **제한된 그룹**을 마우스 오른쪽 단추로 클릭한 후에 **그룹 추가**를 선택합니다.
1. **그룹 추가** 대화 상자의 **그룹** 텍스트 상자에서 **찾아보기**를 선택합니다. 그런 다음 **그룹 선택** 대화 상자의 **선택할 개체 이름을 입력하십시오**. 에 **Local Admins**를 입력하고 **확인**을 선택합니다.
1. **그룹 추가** 대화 상자로 돌아와서 **확인**을 선택합니다.
1. **ADATUM\Local Admins 속성** 대화 상자의 레이블이 **그룹이 가입된 그룹인** 섹션에서 **추가**를 선택합니다. 그런 다음 **그룹 구성원** 대화 상자에 **관리자**를 입력하고 **확인**, **확인**을 차례로 선택하여 변경을 완료합니다.

   >**참고**: 레이블이 **그룹이 가입된 그룹인** 섹션을 사용해야 합니다.

1. az140-cl-vm11a Azure VM에 연결된 원격 데스크톱 세션 내에서 MPowerShell ISE를 관리자 권한으로 시작합니다. 그런 후에 다음 명령을 실행하여 Azure Virtual Desktop 호스트를 다시 시작해 그룹 정책 처리를 트리거합니다.

   ```powershell
   $servers = 'az140-21-p1-0','az140-21-p1-1'
   Restart-Computer -ComputerName $servers -Force -Wait
   ```

1. 스크립트가 완료될 때까지 기다립니다. 이 작업은 3분 정도 걸립니다.

#### 작업 2: Azure Virtual Desktop 세션 호스트 VM에서 FSLogix 기반 프로필 구성

1. **az140-cl-vm11a**에 연결된 원격 데스크톱 세션 내에서 **az140-21-p1-0**으로 연결하는 원격 데스크톱 세션을 시작하고 메시지가 표시되면 **ADATUM\wvdaadmin1** 사용자 이름, 그리고 이 사용자 계정을 만들 때 설정한 암호를 사용하여 로그인합니다. 
1. **az140-21-p1-0**에 연결된 원격 데스크톱 세션 내에서 Microsoft Edge를 시작하고 [FSLogix 다운로드 페이지](https://aka.ms/fslogix_download)로 이동합니다. 그런 다음 압축된 FSLogix 설치 이진 파일을 다운로드하여 **C:\\Source** 폴더에 압축을 풉니다. 그 후에 **x64\\Release** 하위 폴더로 이동한 다음 **FSLogixAppsSetup.exe**를 사용하여 기본 설정으로 Microsoft FSLogix Apps를 설치합니다.

   > **참고**: 이미지가 이미 포함되어 있는지 여부에 따라 FXLogic를 설치할 필요가 없을 수도 있습니다. FX Logix 설치는 재부팅이 필요합니다.

1. **az140-21-p1-0**에 연결된 원격 데스크톱 세션 내에서 **Windows PowerShell ISE**를 관리자 권한으로 시작합니다. 그런 다음 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 PowerShellGet 모듈의 최신 버전을 설치합니다(설치를 확인하라는 메시지가 표시되면 **예** 선택).

   ```powershell
   [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
   Install-Module -Name PowerShellGet -Force -SkipPublisherCheck
   ```

1. **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 Az PowerShell 모듈의 최신 버전을 설치합니다(설치를 확인하라는 메시지가 표시되면 **모두 예** 선택).

   ```powershell
   Install-Module -Name Az -AllowClobber -SkipPublisherCheck
   ```

1. **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 실행 정책을 수정합니다.

   ```powershell
   Set-ExecutionPolicy RemoteSigned -Force
   ```

1. **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 Azure 구독에 로그인합니다.

   ```powershell
   Connect-AzAccount
   ```

1. 메시지가 표시되면 이 랩에서 사용 중인 구독의 Owner 역할이 할당된 사용자 계정의 Azure AD 자격 증명을 사용하여 로그인합니다.
1. **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 이 랩의 앞부분에서 구성한 Azure Storage 계정의 이름을 검색합니다.

   ```powershell
   $resourceGroupName = 'az140-22a-RG'
   $storageAccountName = (Get-AzStorageAccount -ResourceGroupName $resourceGroupName)[0].StorageAccountName   
   ```

1. **az140-21-p1-0**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 프로필 레지스트리 설정을 구성합니다.

   ```powershell
   $profilesParentKey = 'HKLM:\SOFTWARE\FSLogix'
   $profilesChildKey = 'Profiles'
   $fileShareName = 'az140-22a-profiles'
   New-Item -Path $profilesParentKey -Name $profilesChildKey –Force
   New-ItemProperty -Path $profilesParentKey\$profilesChildKey -Name 'Enabled' -PropertyType DWord -Value 1
   New-ItemProperty -Path $profilesParentKey\$profilesChildKey -Name 'VHDLocations' -PropertyType MultiString -Value "\\$storageAccountName.file.core.windows.net\$fileShareName"
   ```

1. **az140-21-p1-0**에 연결된 원격 데스크톱 세션 내에서 **시작**을 마우스 오른쪽 단추로 클릭하고 오른쪽 클릭 메뉴에서 **실행**을 선택합니다. 그런 다음 **실행** 대화 상자의 **열기** 텍스트 상자에 다음 내용을 입력하고 **확인**을 클릭하여 **로컬 사용자 및 그룹** 창을 시작합니다.

   ```cmd
   lusrmgr.msc
   ```

1. **로컬 사용자 및 그룹** 콘솔에서 이름이 **FSLogix** 문자열로 시작되는 그룹 4개를 확인합니다.

   - FSLogix ODFC Exclude List
   - FSLogix ODFC Include List
   - FSLogix Profile Exclude List
   - FSLogix Profile Include List

1. **로컬 사용자 및 그룹** 콘솔에서 **FSLogix Profile Include List** 그룹 항목을 두 번 클릭하여 **\\Everyone** 그룹이 포함되어 있음을 확인합니다. 
그런 후에 **확인**을 선택하여 그룹 **속성** 창을 닫습니다. 
1. **로컬 사용자 및 그룹** 콘솔에서 **FSLogix Profile Exclude List** 그룹 항목을 두 번 클릭하여 기본적으로 아무 그룹 구성원도 포함되어 있지 않음을 확인하고 **확인**을 선택하여 그룹 **속성**창을 닫습니다. 

   > **참고**: 일관성 있는 사용자 환경을 제공하려면 모든 Azure Virtual Desktop 세션 호스트에서 FSLogix 구성 요소를 설치하고 구성해야 합니다. 랩 환경의 다른 세션 호스트에서는 무인 방식으로 이 작업을 수행합니다. 

1. **az140-21-p1-0**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 **az140-21-p1-1** 세션 호스트에 FSLogix 구성 요소를 설치합니다.

   ```powershell
   $server = 'az140-21-p1-1' 
   $localPath = 'C:\Source\x64'
   $remotePath = "\\$server\C$\Source\x64\Release"
   Copy-Item -Path $localPath\Release -Destination $remotePath -Filter '*.exe' -Force -Recurse
   Invoke-Command -ComputerName $server -ScriptBlock {
      Start-Process -FilePath $using:localPath\Release\FSLogixAppsSetup.exe -ArgumentList '/quiet' -Wait
   } 
   ```

1. **az140-21-p1-0**에 연결된 원격 데스크톱 세션 내에서 **Windows PowerShell ISE**를 관리자 권한으로 시작합니다. 그런 다음 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 **az140-21-p1-1** 세션 호스트에서 프로필 레지스트리 설정을 구성합니다.

   ```powershell
   $profilesParentKey = 'HKLM:\SOFTWARE\FSLogix'
   $profilesChildKey = 'Profiles'
   $fileShareName = 'az140-22a-profiles'
   Invoke-Command -ComputerName $server -ScriptBlock {
      New-Item -Path $using:profilesParentKey -Name $using:profilesChildKey –Force
      New-ItemProperty -Path $using:profilesParentKey\$using:profilesChildKey -Name 'Enabled' -PropertyType DWord -Value 1
      New-ItemProperty -Path $using:profilesParentKey\$using:profilesChildKey -Name 'VHDLocations' -PropertyType MultiString -Value "\\$using:storageAccountName.file.core.windows.net\$using:fileShareName"
   }
   ```

   > **참고**: FSLogix 기반 프로필 기능을 테스트하려면 이전 랩에서 사용한 Azure Virtual Desktop 세션 호스트에서 테스트용으로 사용할 ADATUM\wvdaadmin1 계정의 로컬에 캐시된 프로필을 제거해야 합니다.

1. **az140-cl-vm11a**에 연결된 원격 데스크톱 세션으로 전환하여 **az140-cl-vm11a**에 연결된 원격 데스크톱 세션 내에서 **관리자: Windows PowerShell ISE** 창으로 전환한 다음 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 ADATUM\aaduser1 계정의 로컬에 캐시된 프로필을 제거합니다.

   ```powershell
   $userName = 'aaduser1'
   $servers = 'az140-21-p1-0','az140-21-p1-1'
   Get-CimInstance -ComputerName $servers -Class Win32_UserProfile | Where-Object { $_.LocalPath.split('\')[-1] -eq $userName } | Remove-CimInstance
   ```

#### 작업 3: Azure Virtual Desktop을 사용하여 FSLogix 기반 프로필 테스트

1. **az140-cl-vm11a**에 연결된 원격 데스크톱 세션 내에서 Remote Desktop 클라이언트로 전환합니다.
1. **az140-cl-vm11a**에 연결된 원격 데스크톱 세션 내의 **Remote Desktop** 클라이언트 창에 있는 애플리케이션 목록에서 **Command Prompt**를 두 번 클릭합니다. 그런 다음 메시지가 표시되면 암호를 입력하고 **Command Prompt** 창이 시작되는지 확인합니다. 

   > **참고**: 처음에는 애플리케이션이 시작되려면 몇 분 정도 걸릴 수 있지만 그 이후부터는 애플리케이션이 훨씬 빠르게 시작됩니다.

1. **명령 프롬프트** 창 왼쪽 위의 명령 프롬프트 아이콘을 마우스 오른쪽 단추로 클릭하고 드롭다운 메뉴에서 **속성**을 선택합니다.
1. 명령 프롬프트 속성 대화 상자에서 글꼴 탭을 선택하고 크기 및 글꼴 설정을 수정한 후에 확인을 선택합니다.
1. **명령 프롬프트** 창에 **logoff**를 입력하고 **Enter** 키를 눌러 원격 데스크톱 세션에서 로그아웃합니다.
1. **az140-cl-vm11a**에 연결된 원격 데스크톱 세션 내의 **Remote Desktop** 클라이언트 창에 있는 애플리케이션 목록에서 **SessionDesktop**을 두 번 클릭하여 원격 데스크톱 세션이 시작되는지 확인합니다. 
1. **SessionDesktop**세션 내에서 **시작**을 마우스 오른쪽 단추로 클릭하고 오른쪽 클릭 메뉴에서 **실행**을 선택합니다. 그런 다음 **실행** 대화 상자의 **열기** 텍스트 상자에 **cmd**를 입력하고 **확인**을 클릭하여 **명령 프롬프트** 창을 시작합니다.
1. **명령 프롬프트** 창 속성이 이 작업의 앞부분에서 설정한 것과 일치하는지 확인합니다.
1. **SessionDesktop**세션 내에서 모든 창을 최소화하고 바탕 화면을 마우스 오른쪽 단추로 클릭한 후에 오른쪽 클릭 메뉴에서 **새로 만들기**를 선택합니다. 그런 다음 계단식 메뉴에서 **바로 가기**를 선택합니다. 
1. **바로 가기 만들기** 마법사의 **바로 가기를 만들 항목을 선택하십시오.** 페이지에 있는 **항목 위치 입력** 텍스트 상자에 **메모장**을 입력하고 **다음**을 선택합니다.
1. **바로 가기 만들기** 마법사의 **바로 가기의 이름을 지정하십시오.** 페이지에 있는 **바로 가기에 사용할 이름을 입력하십시오.** 텍스트 상자에 **메모장**을 입력하고 **마침**을 선택합니다.
1. **SessionDesktop**세션 내에서 **시작**을 마우스 오른쪽 단추로 클릭하고 오른쪽 클릭 메뉴에서 **종료 또는 로그아웃**을 선택합니다. 그런 다음 계단식 메뉴에서 **로그아웃**을 선택합니다.
1. **az140-cl-vm11a**에 연결된 원격 데스크톱 세션으로 돌아와 **Remote Desktop** 클라이언트 창에 있는 애플리케이션 목록에서 **SessionDesktop**을 두 번 클릭하여 새 원격 데스크톱 세션을 시작합니다. 
1. **SessionDesktop**내에서 **메모장** 바로 가기가 바탕 화면에 표시되는지 확인합니다.
1. **SessionDesktop**세션 내에서 **시작**을 마우스 오른쪽 단추로 클릭하고 오른쪽 클릭 메뉴에서 **종료 또는 로그아웃**을 선택합니다. 그런 다음 계단식 메뉴에서 **로그아웃**을 선택합니다.
1. **az140-cl-vm11a**에 연결된 원격 데스크톱 세션 내에서 Azure Portal이 표시된 Microsoft Edge 창으로 전환합니다.
1. Azure Portal이 표시된 Microsoft Edge 창에서 **스토리지 계정** 블레이드로 이동합니다. 그런 다음 이전 연습에서 만든 스토리지 계정에 해당하는 항목을 선택합니다.
1. 스토리지 계정 블레이드의 **파일 서비스** 섹션에서 **파일 공유**를 선택하고 파일 공유 목록에서 **az140-22a-profiles**를 선택합니다. 
1. 이름이 **ADATUM\\aaduser1** 계정의 SID(보안 식별자) **_aaduser1** 접미사 형식인 폴더가 **az140-22a-profiles** 블레이드의 내용에 포함되어 있는지 확인합니다.
1. 이전 단계에서 확인한 폴더를 선택하여 **Profile_aaduser1.vhd** 파일 하나가 포함되어 있음을 확인합니다.

#### 작업 4: Azure 랩 리소스 삭제

1. [Azure Portal을 사용하여 Azure Active Directory Domain Services 관리형 도메인 삭제]( https://docs.microsoft.com/ko-kr/azure/active-directory-domain-services/delete-aadds)에 설명된 지침을 따라 Azure AD DS 배포를 제거합니다.
1. [Azure Resource Manager 리소스 그룹 및 리소스 삭제](https://docs.microsoft.com/ko-kr/azure/azure-resource-manager/management/delete-resource-group?tabs=azure-portal)에 설명된 지침을 따라 이 과정의 Azure AD DS 랩에서 프로비전한 모든 Azure 리소스 그룹을 제거합니다.
