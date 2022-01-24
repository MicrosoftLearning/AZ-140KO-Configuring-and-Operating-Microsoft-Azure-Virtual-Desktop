---
lab:
    title: '랩: Azure Virtual Desktop 프로필 구현 및 관리(AD DS)'
    module: '모듈 4: 사용자 환경 및 앱 관리'
---

# 랩 - Azure Virtual Desktop 프로필 구현 및 관리(AD DS)
# 학생 랩 매뉴얼

## 랩 종속성

- 이 랩에서 사용할 Azure 구독
- 이 랩에서 사용할 Azure 구독에 대한 Owner 또는 Contributor 역할, 그리고 해당 Azure 구독에 연결된 Azure AD 테넌트의 전역 관리자 역할이 할당되어 있는 Microsoft 계정 또는 Azure AD 계정
- **Azure Virtual Desktop의 배포 준비(AD DS)** 랩 완료
- **랩 - WVD용 스토리지 구현 및 관리(AD DS)** 완료

## 예상 소요 시간

30분

## 랩 시나리오

Active Directory Domain Services(AD DS) 환경에서 Azure Virtual Desktop 프로필 관리를 구현해야 합니다.

## 목표
  
이 랩을 완료하면 다음을 수행할 수 있습니다.

- Azure Virtual Desktop용 FSLogix 기반 프로필 구현

## 랩 파일

- 없음

## 지침

### 연습 1: Azure Virtual Desktop용 FSLogix 기반 프로필 구현

이 연습의 주요 작업은 다음과 같습니다.

1. Azure Virtual Desktop 세션 호스트 VM에서 FSLogix 기반 프로필 구성
1. Azure Virtual Desktop을 사용하여 FSLogix 기반 프로필 테스트
1. 랩에서 배포한 Azure 리소스 제거

#### 작업 1: Azure Virtual Desktop 세션 호스트 VM에서 FSLogix 기반 프로필 구성

1. 랩 컴퓨터에서 웹 브라우저를 시작하고 [Azure Portal](https://portal.azure.com)로 이동합니다. 그런 다음 이 랩에서 사용할 구독의 Owner 역할이 할당된 사용자 계정의 자격 증명을 입력하여 로그인합니다.
1. Azure Portal에서 **가상 머신**을 검색 및 선택하고 **가상 머신** 블레이드에서 **az140-21-p1-0**을 선택합니다.
1. **az140-21-p1-0** 블레이드에서 **시작**을 선택하고 가상 머신의 상태가 **실행 중**으로 바뀔 때까지 기다립니다.
1. **az140-21-p1-0** 블레이드에서 **연결**을 선택하고 드롭다운 메뉴에서 **Bastion**을 선택합니다. 그런 다음 **az140-21-p1-0 \| 연결** 블레이드의 **Bastion** 탭에서 **Bastion 사용**을 선택합니다.
1. 메시지가 표시되면 다음 자격 증명으로 로그인합니다.

   |설정|값|
   |---|---|
   |사용자 이름|**ADATUM\Student**|
   |암호|**Pa55w.rd1234**|

1. **az140-21-p1-0**에 연결된 원격 데스크톱 세션 내에서 Microsoft Edge를 시작하고 [Azure Portal](https://portal.azure.com)로 이동합니다. 메시지가 표시되면 이 랩에서 사용 중인 구독의 Owner 역할이 할당된 사용자 계정의 Azure AD 자격 증명을 사용하여 로그인합니다.
1. **az140-21-p1-0**에 대한 원격 데스크톱 세션 내의 Azure Portal을 표시하는 Microsoft Edge 창에서 Cloud Shell 창 내의 PowerShell 세션을 엽니다. 
1. Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 이 랩에서 사용할 Azure Virtual Desktop 세션 호스트 Azure VM을 시작합니다.

   ```powershell
   Get-AzVM -ResourceGroup 'az140-21-RG' | Start-AzVM
   ```

   >**참고**: Azure VM이 실행될 때까지 기다렸다가 다음 단계를 진행합니다.

1. **az140-21-p1-0**에 연결된 원격 데스크톱 세션 내에서 Microsoft Edge를 시작하고 [FSLogix 다운로드 페이지](https://aka.ms/fslogix_download)로 이동합니다. 그런 다음 압축된 FSLogix 설치 이진 파일을 다운로드하여 **C:\\Allfiles\\Labs\\04** 폴더에 압축을 풉니다(필요하면 폴더를 만듭니다). 그 후에 **x64\\Release** 하위 폴더로 이동하여 **FSLogixAppsSetup.exe** 파일을 두 번 클릭해 **Microsoft FSLogix Apps Setup** 마법사를 시작하고, 기본 설정으로 Microsoft FSLogix Apps 설치 단계를 진행합니다.

   > **참고**: 이미지가 이미 포함되어 있는 경우 FXLogic를 설치할 필요가 없습니다.

3. **az140-21-p1-0**에 연결된 원격 데스크톱 세션 내에서 **Windows PowerShell ISE**를 관리자 권한으로 시작합니다. 그런 다음 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 PowerShellGet 모듈의 최신 버전을 설치합니다(설치를 확인하라는 메시지가 표시되면 **예** 선택).

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
1. **az140-21-p1-0**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 이 랩의 앞부분에서 구성한 Azure Storage 계정의 이름을 검색합니다.

   ```powershell
   $resourceGroupName = 'az140-22-RG'
   $storageAccountName = (Get-AzStorageAccount -ResourceGroupName $resourceGroupName)[0].StorageAccountName   
   ```

1. **az140-21-p1-0**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 프로필 레지스트리 설정을 구성합니다.

   ```powershell
   $profilesParentKey = 'HKLM:\SOFTWARE\FSLogix'
   $profilesChildKey = 'Profiles'
   $fileShareName = 'az140-22-profiles'
   New-Item -Path $profilesParentKey -Name $profilesChildKey –Force
   New-ItemProperty -Path $profilesParentKey\$profilesChildKey -Name 'Enabled' -PropertyType DWord -Value 1
   New-ItemProperty -Path $profilesParentKey\$profilesChildKey -Name 'VHDLocations' -PropertyType MultiString -Value "\\$storageAccountName.file.core.windows.net\$fileShareName"
   ```

1. **az140-21-p1-0**에 연결된 원격 데스크톱 세션 내에서 **시작**을 마우스 오른쪽 단추로 클릭하고 오른쪽 클릭 메뉴에서 **실행**을 선택합니다. 그런 다음 **실행** 대화 상자의 **열기** 텍스트 상자에 다음 내용을 입력하고 **확인**을 클릭하여 **로컬 사용자 및 그룹** 콘솔을 시작합니다.

   ```cmd
   lusrmgr.msc
   ```

1. **로컬 사용자 및 그룹** 콘솔에서 이름이 **FSLogix** 문자열로 시작되는 그룹 4개를 확인합니다.

   - FSLogix ODFC Exclude List
   - FSLogix ODFC Include List
   - FSLogix Profile Exclude List
   - FSLogix Profile Include List

1. **로컬 사용자 및 그룹** 콘솔의 그룹 목록에서 **FSLogix Profile Include List** 그룹을 두 번 클릭하여 **\Everyone** 그룹이 포함되어 있음을 확인하고 **확인**을 선택하여 그룹 **속성** 창을 닫습니다. 
1. **로컬 사용자 및 그룹** 콘솔의 그룹 목록에서 **FSLogix Profile Exclude List** 그룹을 두 번 클릭하여 기본적으로 아무 그룹 구성원도 포함되어 있지 않음을 확인하고 **확인**을 선택하여 그룹 **속성** 창을 닫습니다. 

   > **참고**: 일관성 있는 사용자 환경을 제공하려면 모든 Azure Virtual Desktop 세션 호스트에서 FSLogix 구성 요소를 설치하고 구성해야 합니다. 랩 환경의 다른 세션 호스트에서는 무인 방식으로 이 작업을 수행합니다. 

1. **az140-21-p1-0**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 **az140-21-p1-1** 및 **'az140-21-p1-1'** 세션 호스트에 FSLogix 구성 요소를 설치합니다.

   ```powershell
   $servers = 'az140-21-p1-1', 'az140-21-p1-2'
   foreach ($server in $servers) {
      $localPath = 'C:\Allfiles\Labs\04\x64'
      $remotePath = "\\$server\C$\Allfiles\Labs\04\x64\Release"
      Copy-Item -Path $localPath\Release -Destination $remotePath -Filter '*.exe' -Force -Recurse
      Invoke-Command -ComputerName $server -ScriptBlock {
         Start-Process -FilePath $using:localPath\Release\FSLogixAppsSetup.exe -ArgumentList '/quiet' -Wait
      } 
   }
   ```

   > **참고**: 스크립트 실행이 완료될 때까지 기다립니다. 완료되려면 2분 정도 걸립니다.

1. **az140-21-p1-0**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 **az140-21-p1-1** 및 **az140-21-p1-1** 세션 호스트에 프로필 레지스트리 설정을 구성합니다.

   ```powershell
   $profilesParentKey = 'HKLM:\SOFTWARE\FSLogix'
   $profilesChildKey = 'Profiles'
   $fileShareName = 'az140-22-profiles'
   foreach ($server in $servers) {
      Invoke-Command -ComputerName $server -ScriptBlock {
         New-Item -Path $using:profilesParentKey -Name $using:profilesChildKey –Force
         New-ItemProperty -Path $using:profilesParentKey\$using:profilesChildKey -Name 'Enabled' -PropertyType DWord -Value 1
         New-ItemProperty -Path $using:profilesParentKey\$using:profilesChildKey -Name 'VHDLocations' -PropertyType MultiString -Value "\\$using:storageAccountName.file.core.windows.net\$using:fileShareName"
      }
   }
   ```

   > **참고**: FSLogix 기반 프로필 기능을 테스트하려면 이전 랩에서 사용한 Azure Virtual Desktop 세션 호스트에서 테스트용으로 사용할 **ADATUM\aduser1** 계정의 로컬에 캐시된 프로필을 제거해야 합니다.

1. **az140-21-p1-0**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 세션 호스트로 사용되는 모든 Azure VM에서 **ADATUM\\aduser1** 계정의 로컬에 캐시된 프로필을 제거합니다.

   ```powershell
   $userName = 'aduser1'
   $servers = 'az140-21-p1-0','az140-21-p1-1', 'az140-21-p1-2'
   Get-CimInstance -ComputerName $servers -Class Win32_UserProfile | Where-Object { $_.LocalPath.split('\')[-1] -eq $userName } | Remove-CimInstance
   ```

#### 작업 2: Azure Virtual Desktop을 사용하여 FSLogix 기반 프로필 테스트

1. 랩 컴퓨터로 전환한 후 랩 컴퓨터 내의 Azure Portal이 표시된 브라우저 창에서 **가상 머신**을 검색하여 선택합니다. 그런 다음 **가상 머신** 블레이드에서 **az140-cl-vm11** 항목을 선택합니다.
1. **az140-cl-vm11** 블레이드에서 **연결**을 선택하고 드롭다운 메뉴에서 **Bastion**을 선택합니다. 그런 다음 **az140-cl-vm11 \| 연결** 블레이드의 **Bastion** 탭에서 **Bastion 사용**을 선택합니다.
1. 메시지가 표시되면 다음 자격 증명을 제공하고 **연결**을 선택합니다.

   |설정|값|
   |---|---|
   |사용자 이름|**Student@adatum.com**|
   |암호|**Pa55w.rd1234**|

1. **az140-cl-vm11**에 연결된 원격 데스크톱 세션 내에서 **시작**을 클릭합니다. 그런 다음 **시작** 메뉴에서 **Remote Desktop**을 클릭하여 Remote Desktop 클라이언트를 시작합니다.
1. **az140-cl-vm11**에 연결된 원격 데스크톱 세션 내 **Remote Desktop** 클라이언트 창에서 **제출**을 선택하고 메시지가 표시되면 **aduser1** 자격 증명을 사용하여 로그인합니다.
1. 애플리케이션 목록에서 **명령 프롬프트**를 두 번 클릭하고 메시지가 표시되면 **aduser1** 계정의 암호를 제공하여 **명령 프롬프트** 창이 열리는지 확인합니다.
1. **명령 프롬프트** 창 왼쪽 위의 **명령 프롬프트** 아이콘을 마우스 오른쪽 단추로 클릭하고 드롭다운 메뉴에서 **속성**을 선택합니다.
1. **명령 프롬프트 속성** 대화 상자에서 **글꼴** 탭을 선택하고 크기 및 글꼴 설정을 수정한 후에 **확인**을 선택합니다.
1. **명령 프롬프트** 창에 **logoff**를 입력하고 **Enter** 키를 눌러 원격 데스크톱 세션에서 로그아웃합니다.
1. **az140-cl-vm11**에 연결된 원격 데스크톱 세션 내의 **Remote Desktop** 클라이언트 창에 있는 애플리케이션 목록에서 az-140-21-s1 아래의 **SessionDesktop**을 두 번 클릭하여 원격 데스크톱 세션이 시작되는지 확인합니다. 
1. **SessionDesktop**세션 내에서 **시작**을 마우스 오른쪽 단추로 클릭하고 오른쪽 클릭 메뉴에서 **실행**을 선택합니다. 그런 다음 **실행** 대화 상자의 **열기** 텍스트 상자에 **cmd**를 입력하고 **확인**을 클릭하여 **명령 프롬프트** 창을 시작합니다.
1. **명령 프롬프트** 창 설정이 이 작업의 앞부분에서 구성한 것과 일치하는지 확인합니다.
1. **SessionDesktop**세션 내에서 모든 창을 최소화하고 바탕 화면을 마우스 오른쪽 단추로 클릭한 후에 오른쪽 클릭 메뉴에서 **새로 만들기**를 선택합니다. 그런 다음 계단식 메뉴에서 **바로 가기**를 선택합니다. 
1. **바로 가기 만들기** 마법사의 **바로 가기를 만들 항목을 선택하십시오.** 페이지에 있는 **항목 위치 입력** 텍스트 상자에 **메모장**을 입력하고 **다음**을 선택합니다.
1. **바로 가기 만들기** 마법사의 **바로 가기의 이름을 지정하십시오.** 페이지에 있는 **바로 가기에 사용할 이름을 입력하십시오.** 텍스트 상자에 **메모장**을 입력하고 **마침**을 선택합니다.
1. **SessionDesktop**세션 내에서 **시작**을 마우스 오른쪽 단추로 클릭하고 오른쪽 클릭 메뉴에서 **종료 또는 로그아웃**을 선택합니다. 그런 다음 계단식 메뉴에서 **로그아웃**을 선택합니다.
1. **az140-cl-vm11**에 연결된 원격 데스크톱 세션으로 돌아와 **Remote Desktop** 클라이언트 창에 있는 애플리케이션 목록에서 **SessionDesktop**을 두 번 클릭하여 새 원격 데스크톱 세션을 시작합니다. 
1. **SessionDesktop**내에서 **메모장** 바로 가기가 바탕 화면에 표시되는지 확인합니다.
1. **SessionDesktop**세션 내에서 **시작**을 마우스 오른쪽 단추로 클릭하고 오른쪽 클릭 메뉴에서 **종료 또는 로그아웃**을 선택합니다. 그런 다음 계단식 메뉴에서 **로그아웃**을 선택합니다.
1. 랩 컴퓨터로 전환하여 Azure Portal이 표시된 Microsoft Edge 창에서 **스토리지 계정** 블레이드로 이동합니다. 그런 다음 이전 연습에서 만든 스토리지 계정에 해당하는 항목을 선택합니다.
1. 스토리지 계정 블레이드의 **파일 서비스** 섹션에서 **파일 공유**를 선택하고 파일 공유 목록에서 **az140-22-profiles**를 선택합니다. 
1. 이름이 **ADATUM\aduser1** 계정의 SID(보안 식별자)+**_aduser1** 접미사 형식인 폴더가 **az140-22-profiles** 블레이드의 내용에 포함되어 있는지 확인합니다.
1. 이전 단계에서 확인한 폴더를 선택하여 **Profile_aduser1.vhd** 파일 하나가 포함되어 있음을 확인합니다.

### 연습 2: 랩에서 프로비전 및 사용한 Azure VM 중지 및 할당 취소

이 연습의 주요 작업은 다음과 같습니다.

1. 랩에서 프로비전 및 사용한 Azure VM 중지 및 할당 취소

>**참고**: 이 연습에서는 해당 컴퓨팅 비용을 최소화하기 위해 이 랩에서 프로비전 및 사용한 Azure VM의 할당을 취소합니다.

#### 작업 1: 랩에서 프로비전 및 사용한 Azure VM 할당 취소

1. 랩 컴퓨터로 전환한 다음 Azure Portal이 표시된 웹 브라우저 창에서 **Cloud Shell** 창 내에 **PowerShell** 셸 세션을 엽니다.
1. Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 이 랩에서 만들고 사용한 모든 Azure VM의 목록을 표시합니다.

   ```powershell
   Get-AzVM -ResourceGroup 'az140-21-RG'
   ```

1. Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 이 랩에서 만들고 사용한 모든 Azure VM을 중지하고 할당을 취소합니다.

   ```powershell
   Get-AzVM -ResourceGroup 'az140-21-RG' | Stop-AzVM -NoWait -Force
   ```

   >**참고**: 명령은 비동기적으로 실행되므로(-NoWait 매개 변수에 의해 결정됨) 동일한 PowerShell 세션 내에서 즉시 다른 PowerShell 명령을 실행할 수는 있지만, Azure VM이 실제로 중지 및 할당 취소되려면 몇 분 정도 걸립니다.
