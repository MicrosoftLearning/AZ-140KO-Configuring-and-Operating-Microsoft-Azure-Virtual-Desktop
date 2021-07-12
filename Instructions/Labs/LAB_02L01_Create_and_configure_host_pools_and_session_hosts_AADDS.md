﻿---
lab:
    title: '랩: 호스트 풀 및 세션 호스트 만들기 및 구성(Azure AD DS)'
    module: '모듈 2: WVD 인프라 구현'
---

# 랩 - 호스트 풀 및 세션 호스트 만들기 및 구성(Azure AD DS)
# 학생 랩 매뉴얼

## 랩 종속성

- Azure 구독
- Azure 구독과 연결된 Azure AD 테넌트의 전역 관리자 역할, 그리고 Azure 구독의 소유자 또는 참가자 역할이 할당되어 있는 Microsoft 계정 또는 Azure AD 계정
- **Azure Windows Virtual Desktop의 배포 준비(Azure AD DS)** 랩 완료

## 예상 소요 시간

60분

## 랩 시나리오

Azure Active Directory Domain Services(Azure AD DS) 환경에서 호스트 풀과 세션 호스트를 만들고 구성해야 합니다.

## 목표
  
이 랩을 완료하면 다음을 수행할 수 있습니다.

- Azure AD DS 도메인에서 Azure Windows Virtual Desktop 환경 구성 
- Azure AD DS 도메인에서 Azure Windows Virtual Desktop 환경 유효성 검사 

## 랩 파일

- 없음 

## 지침

### 연습 1: Azure Windows Virtual Desktop 환경 구성
  
이 연습의 기본 작업은 다음과 같습니다.

1. Azure Windows Virtual Desktop 호스트 풀 배포용 AD DS 도메인 및 Azure 구독 준비
1. Azure Windows Virtual Desktop 호스트 풀 배포
1. Windows Virtual Desktop 애플리케이션 그룹 구성
1. Windows Virtual Desktop 작업 영역 구성

#### 작업 1: Azure Windows Virtual Desktop 호스트 풀 배포용 AD DS 도메인 및 Azure 구독 준비

1. 랩 컴퓨터에서 웹 브라우저를 시작하고 [Azure Portal](https://portal.azure.com)로 이동합니다. 그런 다음 이 랩에서 사용할 구독의 소유자 역할이 할당된 사용자 계정의 자격 증명을 입력하여 로그인합니다.
1. 랩 컴퓨터에 표시된 Azure Portal에서 **가상 머신**을 검색하여 선택하고 **가상 머신** 블레이드에서 **az140-cl-vm11a** 항목을 선택합니다. 그러면 **az140-cl-vm11a** 블레이드가 열립니다.
1. **az140-cl-vm11a** 블레이드의 도구 모음에서 **연결**을 선택하고 드롭다운 메뉴에서 **RDP**를 선택합니다. 그런 다음 **az140-cl-vm11a \** **연결** 블레이드의**| RDP** 탭에 있는 **IP 주소** 드롭다운 목록에서 **공용 IP 주소** 항목을 선택한 다음 **RDP 파일 다운로드**를 선택합니다.
1. 메시지가 표시되면 다음 자격 증명으로 로그인합니다.

   |설정|값|
   |---|---|
   |사용자 이름|**ADATUM\\aadadmin1**|
   |암호|**Pa55w.rd1234**|

1. **az140-cl-vm11a** Azure VM에 연결된 원격 데스크톱 세션 내에서 Microsoft Edge를 시작하고 [Azure Portal](https://portal.azure.com)로 이동합니다. 그런 다음 사용자 계정 이름으로 **aadadmin1** 사용자 계정을, 암호로 **Pa55w.rd1234**를 입력하여 로그인합니다.

   >**참고**: **aadadmin1** 계정의 UPN(사용자 계정 이름) 특성을 확인하려면 Active Directory 사용자 및 컴퓨터 콘솔에서 계정의 속성 대화 상자를 검토하거나, 랩 컴퓨터로 돌아가 Azure Portal의 Azure AD 테넌트 블레이드에서 계정 속성을 검토하면 됩니다.

1. **az140-cl-vm11a**에 연결된 원격 데스크톱 세션 내의 Azure Portal이 표시된 Microsoft Edge에서 **Cloud Shell** 내에 PowerShell 세션을 열고 다음 명령을 실행하여 **Microsoft.DesktopVirtualization** 리소스 공급자를 등록합니다.

   ```powershell
   Register-AzResourceProvider -ProviderNamespace Microsoft.DesktopVirtualization
   ```

1. **az140-cl-vm11a**에 연결된 원격 데스크톱 세션 내의 Azure Portal이 표시된 Microsoft Edge에서 **가상 네트워크**를 검색하여 선택한 후 **가상 네트워크** 블레이드에서 **az140-aadds-vnet11a** 항목을 선택합니다. 
1. **az140-aadds-vnet11a** 블레이드에서 **서브넷**을 선택하고 **서브넷** 블레이드에서 **+ 서브넷**을 선택합니다. 그런 다음 **서브넷 추가** 블레이드의 **이름** 텍스트 상자에 **hp1-Subnet**을 입력하고 나머지 설정은 모두 기본값으로 유지한 후 **저장**을 선택합니다. 

#### 작업 2: Azure Windows Virtual Desktop 호스트 풀 배포

1. **az140-cl-vm11a**에 연결된 원격 데스크톱 내의 Azure Portal이 표시된 Microsoft Edge 창에서 **Windows Virtual Desktop**을 검색하여 선택합니다. 그런 다음 **Windows Virtual Desktop** 블레이드 왼쪽의 세로 메뉴에 있는 **관리** 섹션에서 **호스트 풀**을 선택합니다. 그런 후에 **Windows Virtual Desktop \| 호스트 풀** 블레이드에서 **+ 만들기**를 선택합니다. 
1. **호스트 풀 만들기** 블레이드의 **기본** 탭에서 다음 설정을 지정하고 **다음: 가상 머신 >**을 선택합니다.

   |설정|값|
   |---|---|
   |구독|이 랩에서 사용 중인 Azure 구독의 이름|
   |리소스 그룹|새 리소스 그룹 **az140-21a-RG**의 이름|
   |호스트 풀 이름|**az140-21a-hp1**|
   |위치|이 랩의 앞부분에서 Azure AD DS 인스턴스를 배포한 Azure 지역의 이름|
   |유효성 검사 환경|**아니요**|
   |호스트 풀 유형|**풀링됨**|
   |최대 세션 제한|**10**|
   |부하 분산 알고리즘|**폭 우선**|

1. **호스트 풀 만들기** 블레이드의 **가상 머신** 탭에서 다음 설정을 지정하고 **다음: 작업 영역 >**을 선택합니다(*<Azure_AD_domain_name>* 자리 표시자는 Azure AD DS 인스턴스를 배포한 구독과 연결된 Azure AD 테넌트의 이름으로 바꿔야 함).

   |설정|값|
   |---|---|
   |가상 머신 추가|**예**|
   |리소스 그룹|**호스트 풀과 같은 그룹으로 기본 지정됨**|
   |가상 머신 위치|이 랩의 첫 번째 연습에서 리소스를 배포한 Azure 지역의 이름|
   |가상 머신 크기|**Standard D2s v3**|
   |VM 수|**2**|
   |이름 접두사|**az140-21-p1**|
   |이미지 형식|**갤러리**|
   |이미지|**Windows 10 Enterprise 다중 세션, 버전 2004 + Microsoft 365 Apps**|
   |OS 디스크 유형|**표준 SSD**|
   |가상 네트워크|**az140-aadds-vnet11a**|
   |서브넷|**hp1-Subnet(10.10.1.0/24)**|
   |공용 IP|**예**|
   |SKU 구성|**기본**|
   |할당 구성|**동적**|
   |네트워크 보안 그룹|**기본**|
   |공용 인바운드 포트|**아니요**|
   |도메인 또는 단위 지정|**예**|
   |가입할 도메인|**adatum.com**|
   |조직 구성 단위 경로|**OU=AADDC Computers,DC=adatum,DC=com**|
   |AD 도메인 가입 UPN|**aadadmin1@***<Azure_AD_domain_name>*|
   |암호|**Pa55w.rd1234**|

1. **호스트 풀 만들기** 블레이드의 **작업 영역** 탭에서 다음 설정을 지정하고 **검토 + 만들기**를 선택합니다.

   |설정|값|
   |---|---|
   |데스크톱 앱 그룹 등록|**아니요**|

1. **호스트 풀 만들기** 블레이드의 **검토 + 만들기** 탭에서 **만들기**를 선택합니다.

   > **참고**: 배포가 완료될 때까지 기다립니다. 15분 정도 걸립니다.

#### 작업 3: Windows Virtual Desktop 애플리케이션 그룹 구성

1. **az140-cl-vm11a**에 연결된 원격 데스크톱 세션 내의 Azure Portal에서 **Windows Virtual Desktop**을 검색하여 선택한 후 **Windows Virtual Desktop** 블레이드에서 **애플리케이션 그룹**을 선택합니다.
1. **Windows Virtual Desktop \| 애플리케이션 그룹** 블레이드에서 자동 생성된 **az140-21a-hp1-DAG** 데스크톱 애플리케이션 그룹을 선택합니다.
1. **az140-21a-hp1-DAG** 블레이드 왼쪽의 세로 메뉴에 있는 **관리** 섹션에서 **할당**을 선택합니다.
1. **az140-21a-hp1-DAG \| 할당** 블레이드에서 **+ 추가**를 선택합니다.
1. **Azure AD 사용자 또는 사용자 그룹 선택** 블레이드에서 **az140-wvd-apooled**를 선택하고 **선택**을 클릭합니다.
1. **Windows Virtual Desktop \| 애플리케이션 그룹** 블레이드로 다시 이동하여 **+ 만들기**를 선택합니다.
1. **애플리케이션 그룹 만들기** 블레이드의 **기본** 탭에서 다음 설정을 지정하고 **다음: 애플리케이션 >**을 선택합니다.

   |설정|값|
   |---|---|
   |구독|이 랩에서 사용 중인 Azure 구독의 이름|
   |리소스 그룹|**az140-21a-RG**|
   |호스트 풀|**az140-21a-hp1**|
   |애플리케이션 그룹 유형|**RemoteApp**|
   |애플리케이션 그룹 이름|**az140-21a-hp1-Office365-RAG**|

1. **애플리케이션 그룹 만들기** 블레이드의 **애플리케이션** 탭에서 **+ 애플리케이션 추가**를 선택합니다.
1. **애플리케이션 추가** 블레이드에서 다음 설정을 지정하고 **저장**을 선택합니다.

   |설정|값|
   |---|---|
   |애플리케이션 원본|**시작 메뉴**|
   |애플리케이션|**Word**|
   |설명|**Microsoft Word**|
   |명령줄 필요|**아니요**|

1. **애플리케이션 그룹 만들기** 블레이드의 **애플리케이션** 탭으로 돌아와 **+ 애플리케이션 추가**를 선택합니다.
1. **애플리케이션 추가** 블레이드에서 다음 설정을 지정하고 **저장**을 선택합니다.

   |설정|값|
   |---|---|
   |애플리케이션 원본|**시작 메뉴**|
   |애플리케이션|**Excel**|
   |설명|**Microsoft Excel**|
   |명령줄 필요|**아니요**|

1. **애플리케이션 그룹 만들기** 블레이드의 **애플리케이션** 탭으로 돌아와 **+ 애플리케이션 추가**를 선택합니다.
1. **애플리케이션 추가** 블레이드에서 다음 설정을 지정하고 **저장**을 선택합니다.

   |설정|값|
   |---|---|
   |애플리케이션 원본|**시작 메뉴**|
   |애플리케이션|**PowerPoint**|
   |설명|**Microsoft PowerPoint**|
   |명령줄 필요|**아니요**|

1. **애플리케이션 그룹 만들기** 블레이드의 **애플리케이션** 탭으로 돌아와 **다음: 할당 >** 을 선택합니다.
1. **애플리케이션 그룹 만들기** 블레이드의 **할당** 탭에서 **+ Azure AD 사용자 또는 사용자 그룹 추가**를 선택합니다.
1. **Azure AD 사용자 또는 사용자 그룹 선택** 블레이드에서 **az140-wvd-aremote-app**을 선택하고 **선택**을 클릭합니다.
1. **애플리케이션 그룹 만들기** 블레이드의 **할당** 탭으로 돌아와 **다음: 작업 영역 >** 을 선택합니다.
1. **작업 영역 만들기** 블레이드의 **작업 영역** 탭에서 다음 설정을 지정하고 **검토 + 만들기** 를 선택합니다.

   |설정|값|
   |---|---|
   |애플리케이션 그룹 등록|**아니요**|

1. **애플리케이션 그룹 만들기** 블레이드의 **검토 + 만들기** 탭에서 **만들기**를 선택합니다.

   > **참고**: 이제 파일 경로를 기준으로 하여 애플리케이션 그룹을 애플리케이션 원본으로 만듭니다.

1. **az140-cl-vm11a**에 연결된 원격 데스크톱 세션 내에서 **Windows Virtual Desktop**을 검색하여 선택한 후 **Windows Virtual Desktop** 블레이드에서 **애플리케이션 그룹**을 선택합니다.
1. **Windows Virtual Desktop \| 애플리케이션 그룹** 블레이드에서 **+ 만들기** 를 선택합니다. 
1. **애플리케이션 그룹 만들기** 블레이드의 **기본** 탭에서 다음 설정을 지정하고 **다음: 애플리케이션 >**을 선택합니다.

   |설정|값|
   |---|---|
   |구독|이 랩에서 사용 중인 Azure 구독의 이름|
   |리소스 그룹|**az140-21a-RG**|
   |호스트 풀|**az140-21a-hp1**|
   |애플리케이션 그룹 유형|**RemoteApp**|
   |애플리케이션 그룹 이름|**az140-21a-hp1-Utilities-RAG**|

1. **애플리케이션 그룹 만들기** 블레이드의 **애플리케이션** 탭에서 + 애플리케이션 추가를 선택합니다.
1. **애플리케이션 추가** 블레이드에서 다음 설정을 지정하고 **저장**을 선택합니다.

   |설정|값|
   |---|---|
   |애플리케이션 원본|**파일 경로**|
   |애플리케이션 경로|**C:\Windows\system32\cmd.exe**|
   |애플리케이션 이름|**명령 프롬프트**|
   |표시 이름|**명령 프롬프트**|
   |아이콘 경로|**C:\Windows\system32\cmd.exe**|
   |아이콘 색인|**0**|
   |설명|**Windows 명령 프롬프트**|
   |명령줄 필요|**아니요**|

1. **애플리케이션 그룹 만들기** 블레이드의 **애플리케이션** 탭으로 돌아와 **다음: **할당 >을 선택합니다.
1. **애플리케이션 그룹 만들기** 블레이드의 **할당** 탭에서 **+ Azure AD 사용자 또는 사용자 그룹 추가**를 선택합니다.
1. **Azure AD 사용자 또는 사용자 그룹 선택** 블레이드에서 **az140-wvd-aremote-app**과 **az140-wvd-aadmins**를 선택하고 **선택**을 클릭합니다.
1. **애플리케이션 그룹 만들기** 블레이드의 **할당** 탭으로 돌아와 **다음: 작업 영역 >**을 선택합니다.
1. **작업 영역 만들기** 블레이드의 **작업 영역** 탭에서 다음 설정을 지정하고 **검토 + 만들기**를 선택합니다.

   |설정|값|
   |---|---|
   |애플리케이션 그룹 등록|**아니요**|

1. **애플리케이션 그룹 만들기** 블레이드의 **검토 + 만들기** 탭에서 **만들기**를 선택합니다.

#### 작업 4: Windows Virtual Desktop 작업 영역 구성

1. **az140-cl-vm11a**에 연결된 원격 데스크톱 세션 내의 Azure Portal이 표시된 Microsoft Edge 창에서 **Windows Virtual Desktop**을 검색하여 선택한 후 **Windows Virtual Desktop** 블레이드에서 **작업 영역**을 선택합니다.
1. **Windows Virtual Desktop \| 작업 영역** 블레이드에서 **+ 만들기**를 선택합니다. 
1. **작업 영역 만들기** 블레이드의 **기본** 탭에서 다음 설정을 지정하고 **다음: 애플리케이션 그룹 >**을 선택합니다.

   |설정|값|
   |---|---|
   |구독|이 랩에서 사용 중인 Azure 구독의 이름|
   |리소스 그룹|**az140-21a-RG**|
   |작업 영역 이름|**az140-21a-ws1**|
   |식별 이름|**az140-21a-ws1**|

1. **작업 영역 만들기** 블레이드의 **애플리케이션 그룹** 탭에서 다음 설정을 지정합니다.

   |설정|값|
   |---|---|
   |데스크톱 앱 그룹 등록|**예**|

1. **작업 영역 만들기** 블레이드의 **작업 영역** 탭에서 **+ 애플리케이션 그룹 등록**을 선택합니다.
1. **애플리케이션 그룹 추가** 블레이드에서 **az140-21a-hp1-DAG**, **az140-21a-hp1-Office365-RAG** 및 **az140-21a-hp1-Utilities-RAG** 항목 옆의 더하기 기호를 선택하고 **선택**을 클릭합니다. 
1. **작업 영역 만들기** 블레이드의 **애플리케이션 그룹** 탭으로 돌아와 **검토 + 만들기**를 선택합니다.
1. **작업 영역 만들기** 블레이드의 **검토 + 만들기** 탭에서 **만들기**를 선택합니다.

### 연습 2: Azure Windows Virtual Desktop 환경 유효성 검사
  
이 연습의 기본 작업은 다음과 같습니다.

1. Windows 10 컴퓨터에 MSRDC(Microsoft Remote Desktop 클라이언트) 설치
1. Windows Virtual Desktop 작업 영역 구독
1. Windows Virtual Desktop 앱 테스트

#### 작업 1: Windows 10 컴퓨터에 MSRDC(Microsoft Remote Desktop 클라이언트) 설치

1. **az140-cl-vm11a**에 연결된 원격 데스크톱 세션 내에서 Microsoft Edge를 시작하고 [Windows Desktop 클라이언트 다운로드 페이지](https://go.microsoft.com/fwlink/?linkid=2068602)로 이동합니다. 해당 페이지에서 메시지가 표시되면 메시지 내용에 따라 설치를 실행합니다. **Install for all users on this machine** 옵션을 선택합니다. 
1. 설치가 완료되면 Remote Desktop 클라이언트를 시작합니다.

#### 작업 2: Windows Virtual Desktop 작업 영역 구독

1. **Remote Desktop** 클라이언트 창에서 **Subscribe**를 선택하고 메시지가 표시되면 **aaduser1** 자격 증명으로 로그인합니다(사용자 이름으로는 userPrincipalName 특성을 사용하고 암호로는 **Pa55w.rd1234** 사용). 

   > **참고**: Subscribe 옵션 대신 **Remote Desktop** 클라이언트 창에서 **Subscribe with URL**을 선택할 수도 있습니다. 그러면 표시되는 **Subscribe to a Workspace** 창의 **Email or Workspace URL**에 **https://rdweb.wvd.microsoft.com/api/arm/feeddiscovery**를 입력하고 **Next**를 선택합니다. 메시지가 표시되면 **aaduser1** 자격 증명으로 로그인합니다(사용자 이름으로는 userPrincipalName 특성을 사용하고 암호로는 **Pa55w.rd1234** 사용). 

   > **참고**: **aaduser1**의 사용자 계정 이름은 **aaduser1@***<Azure_AD_domain_name>* 형식입니다. 여기서 *<Azure_AD_domain_name>* 자리 표시자는 Azure AD DS 인스턴스를 배포한 구독과 연결된 Azure AD 테넌트의 이름과 일치합니다.

1. **Stay signed in to all your apps** 창에서 **Allow my organization to manage my device** 체크박스 선택을 취소하고 **No, sign in to this app only**를 선택합니다. 
1. **Remote Desktop** 페이지에 **aaduser1** 사용자 계정과 그룹 등록을 통해 연결된 애플리케이션 그룹에 포함되어 있는 애플리케이션 목록이 표시되는지 확인합니다. 

#### 작업 3: Windows Virtual Desktop 앱 테스트

1. **az140-cl-vm11a**에 연결된 원격 데스크톱 세션 내의 **Remote Desktop **클라이언트 창에 있는 애플리케이션 목록에서 **Command Prompt**를 두 번 클릭하여 **Command Prompt** 창이 시작되는지 확인합니다. 인증하라는 메시지가 표시되면 **aaduser1** 사용자 계정의 암호로 **Pa55w.rd1234**를 입력하고 **Remember me** 체크박스를 선택한 후 **OK**를 선택합니다.

   > **참고**: 처음에는 애플리케이션이 시작되려면 몇 분 정도 걸릴 수 있지만 그 이후부터는 애플리케이션이 훨씬 빠르게 시작됩니다.

1. 명령 프롬프트에 **hostname**을 입력하고 **Enter** 키를 눌러 명령 프롬프트가 실행되고 있는 컴퓨터의 이름을 표시합니다.

   > **참고**: 표시되는 이름이 **az140-cl-vm11a**가 아닌 **az140-21-p1-0** 또는 **az140-21-p1-1**인지 확인합니다.

1. 명령 프롬프트에 **logoff**를 입력하고 **Enter** 키를 눌러 현재 원격 앱 세션에서 로그오프합니다.
1. **az140-cl-vm11a**에 연결된 원격 데스크톱 세션 내의 **Remote Desktop** 클라이언트 창에 있는 애플리케이션 목록에서 **SessionDesktop**을 두 번 클릭하여 원격 데스크톱 세션이 시작되는지 확인합니다. 
1. **Default Desktop **세션 내에서 **시작**을 마우스 오른쪽 단추로 클릭하고 **실행**을 선택합니다. 그런 다음 **실행** 대화 상자의 **열기** 텍스트 상자에 **cmd**를 입력하고 **확인**을 선택합니다. 
1. **Default Desktop **세션 내의 명령 프롬프트에 **hostname**을 입력하고 **Enter** 키를 눌러 원격 데스크톱 세션이 실행되고 있는 컴퓨터의 이름을 표시합니다.
1. 표시되는 이름이 **az140-21-p1-0**, **az140-21-p1-1** 또는 **az140-21-p1-2**.인지 확인합니다.