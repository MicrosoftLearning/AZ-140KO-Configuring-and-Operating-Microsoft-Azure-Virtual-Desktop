---
lab:
    title: '랩: 세션 호스트 이미지 만들기 및 관리(AD DS)'
    module: '모듈 2: WVD 인프라 구현'
---

# 랩 - 세션 호스트 이미지 만들기 및 관리(AD DS)
# 학생 랩 매뉴얼

## 랩 종속성

- 이 랩에서 사용할 Azure 구독
- 이 랩에서 사용할 Azure 구독에 대한 Owner 또는 Contributor 역할, 그리고 해당 Azure 구독에 연결된 Azure AD 테넌트의 전역 관리자 역할이 할당되어 있는 Microsoft 계정 또는 Azure AD 계정
- **Azure Virtual Desktop의 배포 준비(AD DS)** 랩 완료

## 예상 시간

60분

## 랩 시나리오

Active Directory Domain Services(AD DS) 환경에서 Azure Virtual Desktop 호스트 이미지를 만들고 관리해야 합니다.

## 목표
  
이 랩을 완료하면 다음을 수행할 수 있습니다.

- WVD 세션 호스트 이미지 만들기 및 관리

## 랩 파일

-  \\\\AZ-140\\AllFiles\\Labs\\02\\az140-25_azuredeployvm25.json
-  \\\\AZ-140\\AllFiles\\Labs\\02\\az140-25_azuredeployvm25.parameters.json

## 지침

### 연습 1: 세션 호스트 이미지 만들기 및 관리
  
이 연습의 주요 작업은 다음과 같습니다.

1. Azure Virtual Desktop 호스트 이미지 구성 준비
1. Azure Bastion 배포
1. Azure Virtual Desktop 호스트 이미지 구성
1. Azure Virtual Desktop 호스트 이미지 만들기
1. 사용자 지정 이미지를 사용하여 Azure Virtual Desktop 호스트 풀 프로비전

#### 작업 1: Azure Virtual Desktop 호스트 이미지 구성 준비

1. 랩 컴퓨터에서 웹 브라우저를 시작하여 [Azure Portal](https://portal.azure.com)로 이동하고 이 랩에서 사용할 구독에서 Owner 역할을 가진 사용자 계정의 자격 증명을 제공하여 로그인합니다.
1. Azure Portal에서 검색 텍스트 상자의 오른쪽에 있는 도구 모음 아이콘을 직접 선택하여 **Cloud Shell** 창을 엽니다.
1. **Bash** 또는 **PowerShell**을 선택하라는 메시지가 표시되면 **PowerShell**을 선택합니다. 
1. 랩 컴퓨터의 Azure Portal이 표시된 웹 브라우저 내 Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 Azure Virtual Desktop 호스트 이미지를 저장할 리소스 그룹을 만듭니다.

   ```powershell
   $vnetResourceGroupName = 'az140-11-RG'
   $location = (Get-AzResourceGroup -ResourceGroupName $vnetResourceGroupName).Location
   $imageResourceGroupName = 'az140-25-RG'
   New-AzResourceGroup -Location $location -Name $imageResourceGroupName
   ```

1. Azure Portal의 Cloud Shell 창 도구 모음에서 **파일 업로드/다운로드** 아이콘을 선택하고 드롭다운 메뉴에서 **업로드**를 선택합니다. 그런 다음 **\\\\AZ-140\\AllFiles\\Labs\\02\\az140-25_azuredeployvm25.json** 및 **\\\\AZ-140\\AllFiles\\Labs\\02\\az140-25_azuredeployvm25.parameters.json** 파일을 Cloud Shell 홈 디렉터리에 업로드합니다.
1. Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 Windows 10을 실행하는 Azure VM을 배포합니다. 이 VM은 새로 만든 서브넷의 Azure Virtual Desktop 클라이언트로 사용됩니다.

   ```powershell
   New-AzResourceGroupDeployment `
     -ResourceGroupName $imageResourceGroupName `
     -Name az140lab0205vmDeployment `
     -TemplateFile $HOME/az140-25_azuredeployvm25.json `
     -TemplateParameterFile $HOME/az140-25_azuredeployvm25.parameters.json
   ```

   > **참고**: 배포가 완료될 때까지 기다린 후 다음 연습을 진행합니다. 배포는 10분 정도 걸릴 수 있습니다.

#### 작업 2: Azure Bastion 배포 

> **참고**: Azure Bastion을 사용하면 이 연습의 이전 작업에서 배포한 공용 엔드포인트 없이 Azure VM에 연결할 수 있으며, 운영 체제 수준 자격 증명을 노리는 무차별 암호 대입 익스플로잇으로부터 보호를 받습니다.

> **참고**: 브라우저에서 팝업 기능이 사용되고 있는지 확인하세요.

1. Azure Portal을 표시하는 브라우저 창에서 다른 탭을 열고, 브라우저 탭에서 Azure Portal로 이동합니다.
1. Azure Portal에서 검색 텍스트 상자의 오른쪽에 있는 도구 모음 아이콘을 직접 선택하여 **Cloud Shell** 창을 엽니다.
1. Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 이 연습 앞부분에서 만든 **az140-25-vnet** 가상 네트워크에 서브넷 **AzureBastionSubnet**을 추가합니다.

   ```powershell
   $resourceGroupName = 'az140-25-RG'
   $vnet = Get-AzVirtualNetwork -ResourceGroupName $resourceGroupName -Name 'az140-25-vnet'
   $subnetConfig = Add-AzVirtualNetworkSubnetConfig `
     -Name 'AzureBastionSubnet' `
     -AddressPrefix 10.25.254.0/24 `
     -VirtualNetwork $vnet
   $vnet | Set-AzVirtualNetwork
   ```

1. Cloud Shell 창을 닫습니다.
1. Azure Portal에서 **Bastion**을 검색하여 선택하고 **Bastion** 블레이드에서 **+ 만들기**를 선택합니다.
1. **Bastion 만들기** 블레이드의 **기본** 탭에서 다음 설정을 지정하고 **검토 + 만들기**를 선택합니다.

   |설정|값|
   |---|---|
   |구독|이 랩에서 사용 중인 Azure 구독의 이름|
   |리소스 그룹|**az140-25-RG**|
   |이름|**az140-25-bastion**|
   |지역|이 연습의 이전 작업에서 리소스를 배포한 것과 동일한 Azure 지역|
   |계층|**기본**|
   |가상 네트워크|**az140-25-vnet**|
   |서브넷|**AzureBastionSubnet (10.25.254.0/24)**|
   |공용 IP 주소|**새로 만들기**|
   |공용 IP 이름|**az140-25-vnet-ip**|

1. **Bastion 만들기** 블레이드의 **검토 + 만들기** 탭에서 **만들기**를 선택합니다.

   > **참고**: 배포가 완료될 때까지 기다린 후 다음 연습을 진행합니다. 배포는 5분 정도 걸릴 수 있습니다.

#### 작업 3: Azure Virtual Desktop 호스트 이미지 구성

1. Azure Portal에서 **가상 머신**을 검색 및 선택하고 **가상 머신** 블레이드에서 **az140-25-vm0**을 선택합니다.
1. **az140-25-vm0** 블레이드에서 **연결**을 선택하고 드롭다운 메뉴에서 **Bastion**을 선택합니다. 그런 다음 **az140-25-vm0 \| 연결** 블레이드의 **Bastion** 탭에서 **Bastion 사용**을 선택합니다.
1. 메시지가 표시되면 다음 자격 증명을 제공하고 **연결**을 선택합니다.

   |설정|값|
   |---|---|
   |사용자 이름|**Student**|
   |암호|**Pa55w.rd1234**|

   > **참고**: 먼저 FSLogix 이진 파일을 설치해야 합니다.

1. **az140-25-vm0**에 연결된 원격 데스크톱 세션 내에서 **Windows PowerShell ISE**를 관리자 권한으로 시작합니다.
1. **az140-25-vm0**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 이미지 구성용 임시 위치로 사용할 폴더를 만듭니다.

   ```powershell
   New-Item -Type Directory -Path 'C:\Allfiles\Labs\02' -Force
   ```

1. **az140-25-vm0**에 연결된 원격 데스크톱 세션 내에서 Microsoft Edge를 시작하고 [FSLogix 다운로드 페이지](https://aka.ms/fslogix_download)로 이동합니다. 그런 다음 압축된 FSLogix 설치 이진 파일을 **C:\\Allfiles\\Labs\\02** 폴더에 다운로드하고, 파일 탐색기에서 같은 폴더에 **x64** 하위 폴더의 압축을 풉니다.
1. **az140-25-vm0**에 연결된 원격 데스크톱 세션 내에서 **관리자: Windows PowerShell ISE** 창으로 전환한 다음 **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 시스템별 OneDrive 설치를 수행합니다.

   ```powershell
   Start-Process -FilePath 'C:\Allfiles\Labs\02\x64\Release\FSLogixAppsSetup.exe' -ArgumentList '/quiet' -Wait
   ```

   > **참고**: 설치가 완료될 때까지 기다립니다. 1분 정도 걸릴 수 있습니다. 설치로 인해 재부팅되면 **az140-25-vm0**에 다시 연결합니다.

   > **참고**: 그 다음에는 Microsoft Teams의 설치 및 구성을 진행합니다(학습 목적을 위해, 이 랩에 사용되는 이미지에 Teams가 이미 존재하기 때문).

1. **az140-25-vm0**에 연결된 원격 데스크톱 세션 내에서 **시작**을 마우스 오른쪽 단추로 클릭하고 오른쪽 클릭 메뉴에서 **실행**을 선택합니다. 그런 다음 **실행** 대화 상자의 **열기** 텍스트 상자에 **cmd**를 입력하고 **Enter** 키를 눌러 **명령 프롬프트**를 시작합니다.
1. **관리자: C:\windows\system32\cmd.exe** 창의 명령 프롬프트에서 다음 명령을 실행하여 Microsoft Teams 시스템별 설치를 준비합니다.

   ```cmd
   reg add "HKLM\Software\Microsoft\Teams" /v IsWVDEnvironment /t REG_DWORD /d 1 /f
   ```

1. **az140-25-vm0**에 연결된 원격 데스크톱 세션 내의 Microsoft Edge에서 [Microsoft Visual C++ 재배포 가능 패키지 다운로드 페이지](https://aka.ms/vs/16/release/vc_redist.x64.exe)로 이동합니다. 그런 다음 **VC_redist.x64**를 **C:\\Allfiles\\Labs\\02** 폴더에 저장합니다.
1. **az140-25-vm0**에 연결된 원격 데스크톱 세션 내에서 **관리자: C:\windows\system32\cmd.exe** 창으로 전환한 후 명령 프롬프트에서 다음 명령을 실행하여 Microsoft Visual C++ 재배포 가능 패키지 설치를 수행합니다.

   ```cmd
   C:\Allfiles\Labs\02\vc_redist.x64.exe /install /passive /norestart /log C:\Allfiles\Labs\02\vc_redist.log
   ```

1. **az140-25-vm0**에 연결된 원격 데스크톱 세션 내의 Microsoft Edge에서 [
VM에 Teams 데스크톱 앱 배포](https://docs.microsoft.com/ko-kr/microsoftteams/teams-for-vdi#deploy-the-teams-desktop-app-to-the-vm) 설명서 페이지로 이동하여 **64비트 버전** 링크를 클릭합니다. 메시지가 표시되면 **Teams_windows_x64.msi** 파일을 **C:\\Allfiles\\Labs\\02** 폴더에 저장합니다.
1. **az140-25-vm0**에 연결된 원격 데스크톱 세션 내에서 **관리자: C:\windows\system32\cmd.exe** 창으로 전환한 후 명령 프롬프트에서 다음 명령을 실행하여 Microsoft Teams 시스템별 설치를 수행합니다.

   ```cmd
   msiexec /i C:\Allfiles\Labs\02\Teams_windows_x64.msi /l*v C:\Allfiles\Labs\02\Teams.log ALLUSER=1
   ```

   > **참고**: 설치 관리자에서는 ALLUSER=1 및 ALLUSERS=1 매개 변수가 지원됩니다. ALLUSER=1 매개 변수는 VDI 환경의 시스템별 설치용입니다. ALLUSERS=1 매개 변수는 VDI 환경과 VDI 이외 환경에서 모두 사용 가능합니다. 

1. **az140-25-vm0**에 연결된 원격 데스크톱 세션 내에서 **Windows PowerShell ISE**를 관리자 권한으로 시작합니다. 그런 다음 **관리자: Windows PowerShell ISE** 콘솔에서 다음을 실행하여 Microsoft Edge Chromium을 설치합니다(학습 목적을 위해, 이 랩에 사용되는 이미지에 Edge가 이미 존재하기 때문).

   ```powershell
   Start-BitsTransfer -Source "https://aka.ms/edge-msi" -Destination 'C:\Allfiles\Labs\02\MicrosoftEdgeEnterpriseX64.msi'
   Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i C:\Allfiles\Labs\02\MicrosoftEdgeEnterpriseX64.msi /q"
   ```

   > **참고**: 설치가 완료될 때까지 기다립니다. 완료되려면 2분 정도 걸립니다.

   > **참고**: 다국어 환경에서 작업할 때는 언어 팩을 설치해야 할 수 있습니다. 이 절차와 관련한 세부 정보는 Microsoft Docs 문서[Windows 10 다중 세션 이미지에 언어 팩 추가](https://docs.microsoft.com/ko-kr/azure/virtual-desktop/language-packs)를 참조하세요.

   > **참고**: 다음으로는 Windows 자동 업데이트와 저장 공간 센스를 사용하지 않도록 설정하고, 표준 시간대 리디렉션과 원격 분석 수집을 구성합니다. 일반적으로는 먼저 모든 현재 업데이트부터 적용해야 합니다. 이 랩에서는 랩 소요 시간을 최소화하기 위해 해당 단계를 건너뜁니다.

1. **az140-25-vm0**에 연결된 원격 데스크톱 세션 내에서 **관리자: C:\windows\system32\cmd.exe** 창으로 전환한 후 명령 프롬프트에서 다음 명령을 실행하여 자동 업데이트를 사용하지 않도록 설정합니다.

   ```cmd
   reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
   ```

1. **관리자: C:\windows\system32\cmd.exe** 창의 명령 프롬프트에서 다음 명령을 실행하여 저장 공간 센스를 사용하지 않도록 설정합니다.

   ```cmd
   reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 01 /t REG_DWORD /d 0 /f
   ```

1. **관리자: C:\windows\system32\cmd.exe** 창의 명령 프롬프트에서 다음 명령을 실행하여 표준 시간대 리디렉션을 구성합니다.

   ```cmd
   reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEnableTimeZoneRedirection /t REG_DWORD /d 1 /f
   ```

1. **관리자: C:\windows\system32\cmd.exe** 창의 명령 프롬프트에서 다음 명령을 실행하여 원격 분석 데이터의 피드백 허브 수집을 사용하지 않도록 설정합니다.

   ```cmd
   reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
   ```

1. **관리자: C:\windows\system32\cmd.exe** 창의 명령 프롬프트에서 다음 명령을 실행하여 이 작업 앞부분에서 만든 임시 폴더를 삭제합니다.

   ```cmd
   rmdir C:\Allfiles /s /q
   ```

1. **관리자: C:\windows\system32\cmd.exe** 창의 명령 프롬프트에서 디스크 정리 유틸리티를 실행하고, 유틸리티 실행이 완료되면 **확인**을 클릭합니다.

   ```cmd
   cleanmgr /d C: /verylowdisk
   ```

#### 작업 4: Azure Virtual Desktop 호스트 이미지 만들기

1. **az140-25-vm0**에 연결된 원격 데스크톱 세션 내의 **관리자: C:\windows\system32\cmd.exe** 창 내 명령 프롬프트에서 sysprep 유틸리티를 실행하여 운영 체제에서 이미지 생성을 준비한 후 운영 체제를 자동 종료합니다.

   ```cmd
   C:\Windows\System32\Sysprep\sysprep.exe /oobe /generalize /shutdown
   ```

   > **참고**: sysprep 프로세스가 완료될 때까지 기다립니다. 완료되려면 2분 정도 걸립니다. 이 프로세스가 완료되면 운영 체제가 자동 종료됩니다. 

1. 랩 컴퓨터의 Azure Portal이 표시된 웹 브라우저에서 **가상 머신**을 검색하여 선택하고 **가상 머신** 블레이드에서 **az140-25-vm0**을 선택합니다.
1. **az140-25-vm0** 블레이드의 **필수** 섹션 위에 있는 도구 모음에서 **새로 고침**을 클릭하여 Azure VM **상태**가 **중지됨**으로 변경되었는지 확인합니다. 그런 다음 **중지**를 클릭하고, VM 중지를 확인하라는 메시지가 표시되면 **확인**을 클릭하여 Azure VM을 **중지됨(할당 취소됨)** 상태로 전환합니다.
1. **az140-25-vm0** 블레이드에서 Azure VM **상태**가 **중지됨(할당 취소됨)** 상태로 변경되었는지 확인하고 도구 모음에서 **캡처**를 클릭합니다. 그러면 **이미지 만들기** 블레이드가 자동으로 표시됩니다.
1. **이미지 만들기** 블레이드의 **기본** 탭에서 다음 설정을 지정합니다.

   |설정|값|
   |---|---|
   |Azure 컴퓨팅 갤러리에 이미지 공유|**예, 이미지 버전으로 갤러리에 공유합니다.**|
   |이미지를 만든 후 이 가상 머신을 자동으로 삭제|체크박스 선택 취소|
   |대상 Azure 컴퓨팅 갤러리|새 갤러리 **az14025imagegallery**의 이름|
   |운영 체제 상태|**일반화됨**|

1. **이미지 만들기** 블레이드의 **기본** 탭에서 **대상 이미지 정의** 텍스트 상자 아래의 **새로 만들기**를 클릭합니다.
1. **이미지 정의 만들기**에서 다음 설정을 지정하고 **확인**을 클릭합니다.

   |설정|값|
   |---|---|
   |이미지 정의 이름|**az140-25-host-image**|
   |게시자|**MicrosoftWindowsDesktop**|
   |제안|**office-365**|
   |SKU|**20h1-evd-o365pp**|

1. **이미지 만들기** 블레이드의 **기본** 탭으로 돌아와 다음 설정을 지정하고 **검토 + 만들기**를 클릭합니다.

   |설정|값|
   |---|---|
   |버전 번호|**1.0.0**|
   |최신 항목에서 제외|체크박스 선택 취소|
   |수명 주기 끝|현재 날짜부터 1년 후|
   |기본 복제본 수|**1**|
   |대상 지역 복제본 수|**1**|
   |스토리지 계정 유형|**프리미엄 SSD**|

1. **이미지 만들기** 블레이드의 **검토 + 만들기** 탭에서 **만들기**를 클릭합니다.

   > **참고**: 배포가 완료될 때까지 기다립니다. 20분 정도 걸릴 수 있습니다.

1. 랩 컴퓨터의 Azure Portal이 표시된 웹 브라우저에서 **Azure 컴퓨팅 갤러리**를 검색하여 선택하고 **Azure 컴퓨팅 갤러리** 블레이드에서 **az14025imagegallery** 항목을 선택합니다. 그런 다음 **az14025imagegallery** 블레이드에서 새로 만든 이미지에 해당하는 **az140-25-host-image** 항목이 있는지 확인합니다.

#### 작업 5: 사용자 지정 이미지를 사용하여 Azure Virtual Desktop 호스트 풀 프로비전

1. 랩 컴퓨터의 Azure Portal에서 Azure Portal 페이지 상단의 **리소스, 서비스 및 문서 검색** 텍스트 상자를 사용하여 **가상 네트워크**를 검색한 후 해당 위치로 이동합니다. 그런 다음 **가상 네트워크** 블레이드에서 **az140-adds-vnet11**을 선택합니다. 
1. **az140-adds-vnet11** 블레이드에서 **서브넷**을 선택하고 **서브넷**블레이드에서 **+ 서브넷**을 선택합니다. 그런 다음 **서브넷 추가** 블레이드에서 다음 설정을 지정하고(나머지 설정은 모두 기본값으로 유지) **저장**을 클릭합니다.

   |설정|값|
   |---|---|
   |이름|**hp4-Subnet**|
   |서브넷 주소 범위|**10.0.4.0/24**|

1. 랩 컴퓨터의 Azure Portal이 표시된 웹 브라우저 창에서 **Azure Virtual Desktop**을 검색하여 선택한 후 **Azure Virtual Desktop** 블레이드에서 **호스트 풀**을 선택합니다. 그런 다음 **Azure Virtual Desktop \| 호스트 풀** 블레이드에서 **+ 추가**를 선택합니다. 
1. **호스트 풀 만들기** 블레이드의 **기본** 탭에서 다음 설정을 지정하고 **다음: 가상 머신 >** 을 선택합니다.

   |설정|값|
   |---|---|
   |구독|이 랩에서 사용 중인 Azure 구독의 이름|
   |리소스 그룹|**az140-25-RG**|
   |호스트 풀 이름|**az140-25-hp4**|
   |위치|이 랩의 첫 번째 연습에서 리소스를 배포한 Azure 지역의 이름|
   |유효성 검사 환경|**아니요**|
   |호스트 풀 유형|**풀링됨**|
   |최대 세션 제한|**50**|
   |부하 분산 알고리즘|**폭 우선**|

1. **호스트 풀 만들기** 블레이드의 **가상 머신** 탭에서 다음 설정을 지정합니다.

   |설정|값|
   |---|---|
   |가상 머신 추가|**예**|
   |리소스 그룹|**호스트 풀과 같은 그룹으로 기본 지정됨**|
   |이름 접두사|**az140-25-p4**|
   |가상 머신 위치|이 랩의 첫 번째 연습에서 리소스를 배포한 Azure 지역의 이름|
   |가용성 옵션|인프라 중복이 필요하지 않습니다.|
   |이미지 형식|**갤러리**|

1. **호스트 풀 만들기** 블레이드의 **가상 머신** 탭에서 **이미지** 드롭다운 목록 바로 아래에 있는 **모든 이미지 보기** 링크를 클릭합니다.
1. **이미지 선택** 블레이드의 **내 항목** 탭을 클릭하고 **공유 이미지**를 클릭한 후 공유 이미지 목록에서 **az140-25-host-image**를 선택합니다. 
1. **호스트 풀 만들기** 블레이드의 **가상 머신** 탭으로 돌아와 다음 설정을 지정하고 **다음: 작업 영역 >을 선택합니다.**

   |설정|값|
   |---|---|
   |가상 머신 크기|**Standard D2s v3**|
   |VM 수|**1**|
   |OS 디스크 유형|**표준 SSD LRS**|
   |가상 네트워크|**az140-adds-vnet11**|
   |서브넷|**hp4-Subnet(10.0.4.0/24)**|
   |네트워크 보안 그룹|**기본**|
   |공용 인바운드 포트|**예**|
   |허용할 인바운드 포트|**RDP**|
   |AD 도메인 가입 UPN|**student@adatum.com**|
   |암호|**Pa55w.rd1234**|
   |도메인 또는 단위 지정|**예**|
   |가입할 도메인|**adatum.com**|
   |조직 구성 단위 경로|**OU=WVDInfra,DC=adatum,DC=com**|
   |사용자 이름|Student|
   |암호|Pa55w.rd1234|
   |암호 확인|Pa55w.rd1234|

1. **호스트 풀 만들기** 블레이드의 **작업 영역** 탭에서 다음 설정을 지정하고 **검토 + 만들기**를 선택합니다.

   |설정|값|
   |---|---|
   |데스크톱 앱 그룹 등록|**아니요**|

1. **호스트 풀 만들기** 블레이드의 **검토 + 만들기** 탭에서 **만들기**를 선택합니다.

   > **참고**: 배포가 완료될 때까지 기다립니다. 10분 정도 걸릴 수 있습니다.

   > **참고**: 사용자 지정 이미지 기반 호스트 배포를 수행한 후에는 [GitHub 리포지토리](https://github.com/The-Virtual-Desktop-Team/)에서 제공되는 Virtual Desktop Optimization Tool을 실행하는 것이 좋습니다.


### 연습 2: 랩에서 프로비전한 Azure VM 중지 및 할당 취소

이 연습의 주요 작업은 다음과 같습니다.

1. 랩에서 프로비전한 Azure VM 중지 및 할당 취소

>**참고**: 이 연습에서는 해당 컴퓨팅 비용을 최소화하기 위해 이 랩에서 프로비전한 Azure VM의 할당을 취소합니다.

#### 작업 1: 랩에서 프로비전한 Azure VM 할당 취소

1. 랩 컴퓨터로 전환한 다음 Azure Portal이 표시된 웹 브라우저 창에서 **Cloud Shell** 창 내에 **PowerShell** 셸 세션을 엽니다.
1. Cloud Shell 창 내의 PowerShell 세션에서 다음 명령을 실행하여 이 랩에서 만든 모든 Azure VM의 목록을 표시합니다.

   ```powershell
   Get-AzVM -ResourceGroup 'az140-25-RG'
   ```

1. Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 이 랩에서 만든 모든 Azure VM을 중지하고 할당을 취소합니다.

   ```powershell
   Get-AzVM -ResourceGroup 'az140-25-RG' | Stop-AzVM -NoWait -Force
   ```

   >**참고**: 명령은 비동기적으로 실행되므로(-NoWait 매개 변수에 의해 결정됨) 동일한 PowerShell 세션 내에서 즉시 다른 PowerShell 명령을 실행할 수는 있지만, Azure VM이 실제로 중지 및 할당 취소되려면 몇 분 정도 걸립니다.
