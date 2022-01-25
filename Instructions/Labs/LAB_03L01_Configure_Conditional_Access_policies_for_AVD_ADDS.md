---
lab:
    title: '랩: WVD용 조건부 액세스 정책 구성(AD DS)'
    module: '모듈 3: 액세스 및 보안 관리'
---

# 랩 - WVD용 조건부 액세스 정책 구성(AD DS)
# 학생 랩 매뉴얼

## 랩 종속성

- Azure 구독
- Azure 구독과 연결된 Azure AD 테넌트의 전역 관리자 역할, 그리고 Azure 구독의 Owner 또는 Contributor 역할이 할당되어 있는 Microsoft 계정 또는 Azure AD 계정
- **Azure Virtual Desktop의 배포 준비(AD DS)** 랩 완료
- **Azure Portal을 사용하여 호스트 풀 및 세션 호스트 배포(AD DS)** 랩 완료

## 예상 시간

60분

## 랩 시나리오

Azure Active Directory(Azure AD) 조건부 액세스를 사용하여 Active Directory Domain Services(AD DS) 환경에서 Azure Virtual Desktop 배포에 대한 액세스를 제어해야 합니다.

## 목표
  
이 랩을 완료하면 다음을 수행할 수 있습니다.

- Azure Virtual Desktop용 Azure Active Directory(Azure AD) 기반 조건부 액세스 준비
- Azure Virtual Desktop용 Azure AD 기반 조건부 액세스 구현

## 랩 파일

- 없음 

## 지침

### 연습 1: Azure Virtual Desktop용 Azure AD 기반 조건부 액세스 준비

이 연습의 주요 작업은 다음과 같습니다.

1. Azure AD Premium P2 라이선스 구성
1. Azure AD MFA(Multi-Factor Authentication) 구성
1. Azure AD MFA용 사용자 등록
1. 하이브리드 Azure AD 조인 구성
1. Azure AD Connect 델타 동기화 트리거

#### 작업 1: Azure AD Premium P2 라이선스 구성

>**참고**: Azure AD 조건부 액세스를 구현하려면 Azure AD Premium P1 또는 P2 라이선스가 필요합니다. 이 랩에서는 30일 평가판을 사용합니다.

1. 랩 컴퓨터에서 웹 브라우저를 시작하고 [Azure Portal](https://portal.azure.com)로 이동합니다. 그런 다음 이 랩에서 사용할 구독의 Owner 역할, 그리고 해당 구독과 연결된 Azure AD 테넌트의 전역 관리자 역할이 할당된 사용자 계정의 자격 증명을 입력하여 로그인합니다.
1. Azure Portal에서 **Azure Active Directory**를 검색 및 선택하여 이 랩에서 사용 중인 Azure 구독과 연결된 Azure AD 테넌트로 이동합니다.
1. Azure Active Directory 블레이드 왼쪽의 세로 메뉴 모음에 있는 **관리** 섹션에서 **사용자**를 클릭합니다. 
1. **사용자 | 모든 사용자(미리 보기)** 블레이드에서 **aduser5**를 선택합니다.
1. **aduser5 | 프로필** 블레이드의 도구 모음에서 **편집**을 클릭합니다. 그런 다음 **설정** 섹션의 **사용 위치** 드롭다운 목록에서 랩 환경이 있는 국가를 선택하고 도구 모음에서 **저장**을 클릭합니다.
1. **aduser5 | 프로필** 블레이드의 **ID** 섹션에서 **aduser5** 계정의 사용자 계정 이름을 확인합니다.

    >**참고**: 값을 기록합니다. 이 랩 뒷부분에서 해당 이름이 필요합니다.

1. **사용자 | 모든 사용자(미리 보기)** 블레이드에서 이 작업을 시작할 때 로그인할 때 사용했던 사용자 계정을 선택합니다. 계정에 **사용 위치**가 할당되어 있지 않으면 이전 단계를 반복합니다. 

    >**참고**: 사용자 계정에 Azure AD Premium P2 라이선스를 할당하려면 **사용 위치** 속성을 설정해야 합니다.

1. **사용자 | 모든 사용자(미리 보기)** 블레이드에서 **aadsyncuser** 사용자 계정을 선택하여 해당 사용자 계정 이름을 확인합니다.

    >**참고**: 값을 기록합니다. 이 랩 뒷부분에서 해당 이름이 필요합니다.

1. Azure Portal에서 Azure AD 테넌트의 **개요** 블레이드로 다시 이동한 후 왼쪽 세로 메뉴 모음에 있는 **관리** 섹션에서 **라이선스**를 클릭합니다.
1. **라이선스 \| 개요** 블레이드 왼쪽의 세로 메뉴 모음에 있는 **관리** 섹션에서 **모든 제품**을 클릭합니다.
1. **라이선스 \| 모든 제품** 블레이드의 도구 모음에서 **+ 사용/구매**를 클릭합니다.
1. **활성화** 블레이드의 **ENTERPRISE MOBILITY + SECURITY E5** 섹션에서 **무료 평가판**을 클릭한 다음 **활성화**를 클릭합니다. 
1. 계속해서 **라이선스 \| 개요** 블레이드에서 브라우저 창을 새로 고쳐 활성화가 정상적으로 완료되었는지 확인합니다. 
1. **라이선스 - 모든 제품** 블레이드에서 **Enterprise Mobility + Security E5** 항목을 선택합니다. 
1. **Enterprise Mobility + Security E5** 블레이드의 도구 모음에서 **+ 할당**을 선택합니다.
1. **라이선스 할당** 블레이드에서 **사용자 및 그룹 추가**를 클릭하고 **사용자 및 그룹 추가** 블레이드에서 **aduser5** 및 자신의 사용자 계정을 선택한 후에 **선택**을 클릭합니다.
1. **라이선스 할당** 블레이드에서 **할당 옵션**을 클릭하고 **할당 옵션** 블레이드에서 모든 옵션이 사용하도록 설정되어 있는지 확인한 후에 **검토 + 할당**, **할당**을 차례로 클릭합니다.

#### 작업 2: Azure AD MFA(Multi-Factor Authentication) 구성

1. 랩 컴퓨터의 Azure Portal이 표시된 웹 브라우저에서 Azure AD 테넌트의 **개요**블레이드로 다시 이동한 후 왼쪽 세로 메뉴에 있는 **관리** 섹션에서 **보안**을 클릭합니다.
1. **보안 | 시작** 블레이드 왼쪽의 세로 메뉴에 있는 **관리** 섹션에서 **ID 보호**를 클릭합니다.
1. **ID 보호 | 개요** 블레이드 왼쪽의 세로 메뉴에 있는 **보호** 섹션에서 **MFA 등록 정책**을 클릭합니다(필요한 경우 웹 브라우저 페이지 새로 고침) .
1. **ID 보호 | MFA 등록 정책** 블레이드 **다단계 인증 등록 정책**의 **할당** 섹션에서 **모든 사용자**를 클릭합니다. 그런 다음 **포함** 탭에서 **선택한 개인 및 그룹** 옵션을 클릭하고 **사용자 선택**에서 **aduser5**를 클릭한 후에 **선택**을 클릭합니다. 그 후에 블레이드 아래쪽에서 **정책 적용** 스위치를 **켜기**로 설정하고 **저장**을 클릭합니다.

#### 작업 3: Azure AD MFA용 사용자 등록

1. 랩 컴퓨터에서 **InPrivate** 웹 브라우저 세션을 열고 [Azure Portal](https://portal.azure.com)로 이동합니다. 그런 다음 이 연습 앞부분에서 확인한 **aduser5** 사용자 계정 이름과 이 사용자 계정을 만들 때 설정한 암호를 입력하여 로그인합니다.
1. **자세한 정보 필요** 메시지가 표시되면 **다음**을 클릭합니다. 그러면 브라우저가 **Microsoft Authenticator** 페이지로 자동 리디렉션됩니다.
1. **추가 보안 인증** 페이지의 **1단계: 어떻게 연락해야 하나요?** 에서 원하는 인증 방법을 선택하고 지침을 따라 등록 프로세스를 완료합니다. 
1. Azure Portal 페이지 오른쪽 위에서 사용자 아바타에 해당하는 아이콘을 클릭하고 **로그아웃**을 클릭한 후에 **In private** 브라우저 창을 닫습니다. 

#### 작업 4: 하이브리드 Azure AD 조인 구성

> **참고**: Azure AD 조인 상태를 기준으로 디바이스용 조건부 액세스를 설정할 때 이 기능을 활용하면 추가 보안을 구현할 수 있습니다.

1. 랩 컴퓨터의 Azure Portal이 표시된 웹 브라우저에서 **가상 머신**을 검색하여 선택하고 **가상 머신** 블레이드에서 **az140-dc-vm11**을 선택합니다.
1. **az140-dc-vm11** 블레이드에서 **연결**을 선택하고 드롭다운 메뉴에서 **Bastion**을 선택합니다. 그런 다음 **az140-dc-vm11 \| 연결** 블레이드의 **Bastion** 탭에서 **Bastion 사용**을 선택합니다.
1. 메시지가 표시되면 다음 자격 증명을 제공하고 **연결**을 선택합니다.

   |설정|값|
   |---|---|
   |사용자 이름|**Student**|
   |암호|**Pa55w.rd1234**|

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **시작**메뉴에서 **Azure AD Connect** 폴더를 확장하고 **Azure AD Connect**를 선택합니다.
1. **Microsoft Azure Active Directory Connect** 창의 **Azure AD Connect 시작** 페이지에서 **구성**을 선택합니다.
1. **Microsoft Azure Active Directory Connect** 창의 **추가 작업** 페이지에서 **디바이스 옵션 구성**을 선택하고 **다음**을 선택합니다.
1. **Microsoft Azure Active Directory Connect** 창의 **개요** 페이지에서 **하이브리드 Azure AD 조인** 및 **디바이스 쓰기 저장** 관련 정보를 검토하고 **다음**을 선택합니다.
1. **Microsoft Azure Active Directory Connect** 창의 **AD Azure에 연결** 페이지에서 이전 연습에서 만든 **aadsyncuser** 사용자 계정의 자격 증명을 사용하여 인증하고 **다음**을 선택합니다. 

   > **참고**: 이 랩 앞부분에서 적어 둔 **aadsyncuser** 계정의 userPrincipalName 특성을 입력하고, 이 사용자 계정을 만들 때 설정한 암호를 지정합니다. 

1. **Microsoft Azure Active Directory Connect** 창의 **디바이스 옵션** 페이지에서 **하이브리드 Azure AD 조인 구성** 옵션이 선택되어 있는지 확인하고 **다음**을 선택합니다. 
1. **Microsoft Azure Active Directory Connect** 창의 **디바이스 운영 체제** 페이지에서 **Windows 10 이상 도메인 조인 디바이스** 체크박스를 선택하고 **다음**을 선택합니다. 
1. **Microsoft Azure Active Directory Connect** 창의 **SCP 구성** 페이지에서 **adatum.com** 항목 옆의 체크박스를 선택합니다. 그런 다음 **인증 서비스** 드롭다운 목록에서 **Azure Active Directory** 항목을 선택하고 **추가**를 선택합니다. 
1. 메시지가 표시되면 **엔터프라이즈 관리자 자격 증명** 대화 상자에서 다음 자격 증명을 지정하고 **확인**을 선택합니다.

   |설정|값|
   |---|---|
   |사용자 이름|**ADATUM\Student**|
   |암호|**Pa55w.rd1234**|

1. **Microsoft Azure Active Directory Connect** 창의 **SCP 구성** 페이지로 돌아와서 **다음**을 선택합니다.
1. **Microsoft Azure Active Directory Connect** 창의 **구성 준비 완료** 페이지에서 **구성**을 선택하고 구성이 완료되면 **끝내기**를 선택합니다.
1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내에서 **Windows PowerShell ISE**를 관리자 권한으로 시작합니다.
1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 **az140-cl-vm11** 컴퓨터 계정을 **WVDClients** OU(조직 구성 단위)로 이동합니다.

   ```powershell
   Move-ADObject -Identity "CN=az140-cl-vm11,CN=Computers,DC=adatum,DC=com" -TargetPath "OU=WVDClients,DC=adatum,DC=com"
   ```

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **시작**메뉴에서 **Azure AD Connect** 폴더를 확장하고 **Azure AD Connect**를 선택합니다.
1. **Microsoft Azure Active Directory Connect** 창의 **Azure AD Connect 시작** 페이지에서 **구성**을 선택합니다.
1. **Microsoft Azure Active Directory Connect** 창의 **추가 작업** 페이지에서 **동기화 옵션 사용자 지정**을 선택하고 **다음**을 선택합니다.
1. **Microsoft Azure Active Directory Connect** 창의 **AD Azure에 연결** 페이지에서 이전 연습에서 만든 **aadsyncuser** 사용자 계정의 자격 증명을 사용하여 인증하고 **다음**을 선택합니다. 

   > **참고**: 이 랩 앞부분에서 적어 둔 **aadsyncuser** 계정의 userPrincipalName 특성을 입력하고, 이 사용자 계정을 만들 때 설정한 암호를 지정합니다. 

1. **Microsoft Azure Active Directory Connect** 창의 **디렉터리 연결** 페이지에서 **다음**을 선택합니다.
1. **Microsoft Azure Active Directory Connect** 창의 **도메인 및 OU 필터링** 페이지에서 **선택한 도메인 및 OU 동기화** 옵션이 선택되어 있는지 확인합니다. 그런 다음 **adatum.com** 노드를 확장하여 **ToSync** OU 옆의 체크박스가 선택되어 있는지 확인하고 **WVDClients** OU 옆의 체크박스를 선택한 후 **다음**을 선택합니다.
1. **Microsoft Azure Active Directory Connect** 창의 **선택적 기능** 페이지에서 기본 설정을 적용하고 **다음**을 선택합니다.
1. **Microsoft Azure Active Directory Connect** 창의 **구성 준비 완료** 페이지에서 **구성이 완료되면 동기화 프로세스를 시작합니다.** 체크박스가 선택되었는지 확인하고 **구성**을 선택합니다.
1. **구성 완료** 페이지의 정보를 검토하고 **끝내기**를 선택하여 **Microsoft Azure Active Directory Connect** 창을 닫습니다.

#### 작업 5: Azure AD Connect 델타 동기화 트리거

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내에서 **관리자: Windows PowerShell ISE** 창으로 전환합니다.
1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell** 콘솔 창에서 다음 명령을 실행하여 Azure AD Connect 델타 동기화를 트리거합니다.

   ```powershell
   Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync"
   Start-ADSyncSyncCycle -PolicyType Initial
   ```

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내에서 Microsoft Edge를 시작하고 [Azure Portal](https://portal.azure.com)로 이동합니다. 메시지가 표시되면 이 랩에서 사용 중인 Azure 구독과 연결된 Azure AD 테넌트의 전역 관리자 역할이 할당된 사용자 계정의 Azure AD 자격 증명을 사용하여 로그인합니다.
1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 Azure Portal이 표시된 Microsoft Edge 창에서 **Azure Active Directory**를 검색하여 선택해 이 랩에서 사용 중인 Azure 구독과 연결된 Azure AD 테넌트로 이동합니다.
1. Azure Active Directory 블레이드 왼쪽의 세로 메뉴 모음에 있는 **관리** 섹션에서 **디바이스**를 클릭합니다. 
1. **디바이스 | 모든 디바이스** 블레이드에서 디바이스 목록을 검토하여 **조인 유형** 열에 **az140-cl-vm11** 디바이스가 **하이브리드 Azure AD 조인** 항목과 함께 표시되어 있는지 확인합니다.

   > **참고**: Azure Portal에 디바이스가 표시되기 전에 동기화가 적용되기까지 몇 분 기다려야 할 수도 있습니다.

### 연습 2: Azure Virtual Desktop용 Azure AD 기반 조건부 액세스 구현

이 연습의 주요 작업은 다음과 같습니다.

1. 모든 Azure Virtual Desktop 연결용 Azure AD 기반 조건부 액세스 정책 만들기
1. 모든 Azure Virtual Desktop 연결용 Azure AD 기반 조건부 액세스 정책 테스트
1. Azure AD 기반 조건부 액세스 정책을 수정하여 MFA 요구 사항에서 하이브리드 Azure AD 조인 컴퓨터 제외
1. 수정된 Azure AD 기반 조건부 액세스 정책 테스트

#### 작업 1: 모든 Azure Virtual Desktop 연결용 Azure AD 기반 조건부 액세스 정책 만들기

>**참고**: 이 작업에서는 Azure Virtual Desktop 세션에 로그인하려면 MFA를 사용해야 하는 Azure AD 기반 조건부 액세스 정책을 구성합니다. 또한 이 정책은 정상 인증 후 첫 4시간이 지나면 재인증을 강제 적용합니다.

1. 랩 컴퓨터의 Azure Portal이 표시된 웹 브라우저에서 Azure AD 테넌트의 **개요**블레이드로 다시 이동한 후 왼쪽 세로 메뉴에 있는 **관리** 섹션에서 **보안**을 클릭합니다.
1. **보안 \| 시작** 블레이드 왼쪽의 세로 메뉴에 있는 **보호** 섹션에서 **조건부 액세스**를 클릭합니다.
1. **조건부 액세스 \| 정책** 블레이드의 도구 모음에서 **+ 새 정책**을 클릭합니다. 
1. **새로 만들기** 블레이드에서 다음 설정을 구성합니다.

   - **이름** 텍스트 상자에 **az140-31-wvdpolicy1**을 입력합니다.
   - **할당** 섹션에서 **사용자 및 그룹**을 클릭하고 **사용자 및 그룹** 옵션, **사용자 및 그룹** 체크박스를 차례로 클릭합니다. 그런 다음 **선택** 블레이드에서 **aduser5**를 클릭하고 **선택**을 클릭합니다.
   - **할당** 섹션에서 **클라우드 앱 또는 작업**을 클릭하고 **이 정책을 적용할 항목을 선택합니다.** 스위치에서 **클라우드 앱** 옵션이 선택되어 있는지 확인합니다. 그런 다음 **앱 선택** 옵션을 클릭하고 **선택** 블레이드에서 **Windows Virtual Desktop** 항목 옆의 체크박스를 선택한 후에 **선택**을 클릭합니다. 
   - **할당** 섹션에서 **조건**을 클릭하고 **클라이언트 앱**을 클릭합니다. 그런 다음 **클라이언트 앱** 블레이드에서 **구성** 스위치를 **예**로 설정하고 **브라우저**와 **모바일 앱 및 데스크톱 클라이언트** 체크박스가 모두 선택되어 있는지 확인한 후 **완료**를 클릭합니다.
   - **액세스 제어** 섹션에서 **권한 부여**를 클릭하고 **권한 부여** 블레이드에서 **액세스 허용** 옵션이 선택되었는지 확인합니다. 그런 다음 **다단계 인증 필요** 체크박스를 선택하고 **선택**을 클릭합니다.
   - **액세스 제어** 섹션에서 **세션**을 클릭하고 **세션** 블레이드에서 **로그인 빈도** 체크박스를 선택합니다. 첫 번째 텍스트 상자에는 **4**를 입력하고, **단위 선택** 드롭다운 목록에서 **시간**을 선택합니다. **영구 브라우저 세션** 체크박스는 선택하지 않은 상태로 유지하고 **선택**을 클릭합니다.
   - **정책 사용** 스위치를 **켜기**로 설정합니다.

1. **새로 만들기** 블레이드에서 **만들기**를 선택합니다. 

#### 작업 2: 모든 Azure Virtual Desktop 연결용 Azure AD 기반 조건부 액세스 정책 테스트

1. 랩 컴퓨터의 Azure Portal이 표시된 웹 브라우저 창에서 **Cloud Shell** 창 내에 **PowerShell** 셸 세션을 엽니다.
1. Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 이 랩에서 사용할 Azure Virtual Desktop 세션 호스트 Azure VM을 시작합니다.

   ```powershell
   Get-AzVM -ResourceGroup 'az140-21-RG' | Start-AzVM
   ```

   >**참고**: 명령이 완료되고 **az140-21-RG** 리소스 그룹에 있는 모든 Azure VM이 실행될 때까지 기다립니다. 

1. 랩 컴퓨터에서 **InPrivate** 웹 브라우저 세션을 열고 [Azure Portal](https://portal.azure.com)로 이동합니다. 그런 다음 이 연습 앞부분에서 확인한 **aduser5** 사용자 계정 이름과 이 사용자 계정을 만들 때 설정한 암호를 입력하여 로그인합니다.

   > **참고**: MFA를 통해 인증하라는 메시지가 표시되지 않음을 확인합니다.

1. **InPrivate** 웹 브라우저 Azure Virtual Desktop HTML5 웹 클라이언트 페이지 [https://rdweb.wvd.microsoft.com/arm/webclient](https://rdweb.wvd.microsoft.com/arm/webclient)로 이동합니다.

   > **참고**: 이 페이지로 이동하면 MFA를 통한 인증이 자동으로 트리거되는지 확인합니다.

1. 휴대폰에 수신된 문자에 포함되어 있는 코드를 **코드 입력** 창에 입력하고 **확인**을 클릭합니다.
1. **모든 리소스** 페이지에서 **명령 프롬프트**를 클릭하고 **로컬 리소스 액세스** 창에서 **프린터** 체크박스 선택을 취소한 후에 **허용을** 클릭합니다.
1. 메시지가 표시되면 사용자 **자격 증명 입력**의 **사용자 이름** 텍스트 상자에는 **aduser5**의 사용자 계정 이름을, **암호** 텍스트 상자에는 이 사용자 계정을 만들 때 설정한 암호를 입력하고 **제출**을 클릭합니다.
1. **명령 프롬프트** 원격 앱이 정상적으로 시작되었는지 확인합니다.
1. **명령 프롬프트** 원격 앱 창의 명령 프롬프트에 **logoff**를 입력하고 **Enter** 키를 누릅니다.
1. **모든 리소스** 페이지로 돌아와 오른쪽 위에서 **aduser5**를 클릭하고 드롭다운 메뉴에서 **로그아웃**을 클릭한 다음 **InPrivate** 웹 브라우저 창을 닫습니다.

#### 작업 3: Azure AD 기반 조건부 액세스 정책을 수정하여 MFA 요구 사항에서 하이브리드 Azure AD 조인 컴퓨터 제외

>**참고**: 이 작업에서는 Azure Virtual Desktop 세션에 로그인하려면 MFA를 사용해야 하는 Azure AD 기반 조건부 액세스 정책을 수정하여 Azure AD 조인 컴퓨터에서 시작되는 연결에는 MFA를 사용하지 않아도 되도록 설정합니다.

1. 랩 컴퓨터의 Azure Portal이 표시된 브라우저 창 내 **조건부 액세스 | 정책** 블레이드에서 **az140-31-wvdpolicy1** 정책에 해당하는 항목을 클릭합니다.
1. **az140-31-wvdpolicy1** 블레이드의 **액세스 제어** 섹션에서 **권한 부여**를 클릭하고 **권한 부여** 블레이드에서 **다단계 인증 필요** 및 **하이브리드 Azure AD 조인 디바이스 필요** 체크박스를 선택합니다. 그런 후에 **선택한 컨트롤 중 하나가 필요함** 옵션이 사용하도록 설정되어 있는지 확인하고 **선택**을 클릭합니다.
1. **az140-31-wvdpolicy1** 블레이드에서 **저장**을 클릭합니다.

>**참고**: 정책을 적용하는 데 몇 분 정도 걸릴 수 있습니다.

#### 작업 4: 수정된 Azure AD 기반 조건부 액세스 정책 테스트

1. 랩 컴퓨터의 Azure Portal이 표시된 브라우저 창에서 **가상 머신**을 검색하여 선택합니다. 그런 다음 **가상 머신** 블레이드에서 **az140-cl-vm11** 항목을 선택합니다.
1. **az140-cl-vm11** 블레이드에서 **연결**을 선택하고 드롭다운 메뉴에서 **Bastion**을 선택합니다. 그런 다음 **az140-cl-vm11 \| 연결** 블레이드의 **Bastion** 탭에서 **Bastion 사용**을 선택합니다.
1. 메시지가 표시되면 다음 자격 증명을 제공하고 **연결**을 선택합니다.

   |설정|값|
   |---|---|
   |사용자 이름|**Student@adatum.com**|
   |암호|**Pa55w.rd1234**|

1. **az140-cl-vm11**에 연결된 원격 데스크톱 세션 내에서 Microsoft Edge를 시작하고 Azure Virtual Desktop HTML5 웹 클라이언트 페이지 [https://rdweb.wvd.microsoft.com/arm/webclient](https://rdweb.wvd.microsoft.com/arm/webclient)로 이동합니다.

   > **참고**: 이번에는 MFA를 통해 인증하라는 메시지가 표시되지 않음을 확인합니다. **az140-cl-vm11**이 하이브리드 Azure AD 조인 디바이스이기 때문입니다.

1. **모든 리소스** 페이지에서 **명령 프롬프트**를 클릭하고 **로컬 리소스 액세스** 창에서 **프린터** 체크박스 선택을 취소한 후에 **허용**을 클릭합니다.
1. 메시지가 표시되면 **사용자 자격 증명 입력**의 **사용자 이름** 텍스트 상자에는 **aduser5**의 사용자 계정 이름을, **암호** 텍스트 상자에는 이 사용자 계정을 만들 때 설정한 암호를 입력하고 **제출**을 클릭합니다.
1. **명령 프롬프트** 원격 앱이 정상적으로 시작되었는지 확인합니다.
1. **명령 프롬프트** 원격 앱 창의 명령 프롬프트에 **logoff**를 입력하고 **Enter** 키를 누릅니다.
1. **모든 리소스** 페이지로 돌아와 오른쪽 위에서 **aduser5**를 클릭하고 드롭다운 메뉴에서 **로그아웃**을 클릭합니다.
1. **az140-cl-vm11**에 연결된 원격 데스크톱 세션 내에서 **시작**을 클릭합니다. 그런 다음 **시작** 단추 바로 위의 세로 막대에서 로그인한 사용자 계정에 해당하는 아이콘을 클릭하고 팝업 메뉴에서 **로그아웃**을 클릭합니다.

### 연습 3: 랩에서 프로비전 및 사용한 Azure VM 중지 및 할당 취소

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
