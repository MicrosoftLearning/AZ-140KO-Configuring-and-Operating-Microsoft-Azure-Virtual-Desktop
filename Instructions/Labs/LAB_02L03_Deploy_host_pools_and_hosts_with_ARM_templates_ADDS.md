---
lab:
    title: '랩: Azure Resource Manager 템플릿을 사용하여 호스트 풀 및 호스트 배포'
    module: '모듈 2: WVD 인프라 구현'
---

# 랩 - Azure Resource Manager 템플릿을 사용하여 호스트 풀 및 호스트 배포
# 학생 랩 매뉴얼

## 랩 종속성

- 이 랩에서 사용할 Azure 구독
- 이 랩에서 사용할 Azure 구독에 대한 Owner 또는 Contributor 역할, 그리고 해당 Azure 구독에 연결된 Azure AD 테넌트의 전역 관리자 역할이 할당되어 있는 Microsoft 계정 또는 Azure AD 계정
- **Azure Virtual Desktop의 배포 준비(AD DS)** 랩 완료
- **Azure Portal을 사용하여 호스트 풀 및 세션 호스트 배포(AD DS)** 랩 완료

## 예상 시간

45분

## 랩 시나리오

Azure Resource Manager 템플릿을 사용하여 Azure Virtual Desktop 호스트 풀 및 호스트 배포를 자동화해야 합니다.

## 목표
  
이 랩을 완료하면 다음을 수행할 수 있습니다.

- Azure Resource Manager 템플릿을 사용하여 Azure Virtual Desktop 호스트 풀 및 호스트 배포

## 랩 파일

-  \\\\AZ-140\\AllFiles\\Labs\\02\\az140-23_azuredeployhp23.parameters.json
-  \\\\AZ-140\\AllFiles\\Labs\\02\\az140-23_azuremodifyhp23.parameters.json

## 지침

### 연습 1: Azure Resource Manager 템플릿을 사용하여 Azure Virtual Desktop 호스트 풀 및 호스트 배포
  
이 연습의 주요 작업은 다음과 같습니다.

1. Azure Resource Manager 템플릿을 사용하여 Azure Virtual Desktop 호스트 풀의 배포 준비
1. Azure Resource Manager 템플릿을 사용하여 Azure Virtual Desktop 호스트 풀 및 호스트 배포
1. Azure Virtual Desktop 호스트 풀 및 호스트 배포 확인
1. Azure Resource Manager 템플릿을 사용하여 기존 Azure Virtual Desktop 호스트 풀에 호스트를 추가하는 작업 준비
1. Azure Resource Manager 템플릿을 사용하여 기존 Azure Virtual Desktop 호스트 풀에 호스트 추가
1. Azure Virtual Desktop 호스트 풀의 변경 내용 확인
1. Azure Virtual Desktop 호스트 풀에서 개인 데스크톱 할당 관리

#### 작업 1: Azure Resource Manager 템플릿을 사용하여 Azure Virtual Desktop 호스트 풀의 배포 준비

1. 랩 컴퓨터에서 웹 브라우저를 시작하여 [Azure Portal](https://portal.azure.com)로 이동하고 이 랩에서 사용할 구독에서 Owner 역할을 가진 사용자 계정의 자격 증명을 제공하여 로그인합니다.
1. Azure Portal에서 **가상 머신**을 검색하여 선택하고 **가상 머신** 블레이드에서 **az140-dc-vm11**을 선택합니다.
1. **az140-dc-vm11** 블레이드에서 **연결**을 선택하고 드롭다운 메뉴에서 **Bastion**을 선택합니다. 그런 다음 **az140-dc-vm11 \| 연결** 블레이드의 **Bastion** 탭에서 **Bastion 사용**을 선택합니다.
1. 메시지가 표시되면 다음 자격 증명을 제공하고 **연결**을 선택합니다.

   |설정|값|
   |---|---|
   |사용자 이름|**Student**|
   |암호|**Pa55w.rd1234**|

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내에서 **Windows PowerShell ISE**를 관리자 권한으로 시작합니다.
1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 **WVDInfra** 조직 구성 단위의 고유 이름을 확인합니다. 이 조직 구성 단위는 Azure Virtual Desktop 풀 호스트의 컴퓨터 개체를 호스트합니다.

   ```powershell
   (Get-ADOrganizationalUnit -Filter "Name -eq 'WVDInfra'").distinguishedName
   ```

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 AD DS 도메인(**student@adatum.com**)에 Azure Virtual Desktop 호스트를 조인하는 데 사용할 **ADATUM\\Student** 계정의 사용자 계정 이름 특성을 확인합니다.

   ```powershell
   (Get-ADUser -Filter "sAMAccountName -eq 'student'").userPrincipalName
   ```

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 이 랩 뒷부분에서 개인 데스크톱 할당을 테스트하는 데 사용할 **ADATUM\\aduser7** 및 **ADATUM\\aduser8** 계정의 사용자 계정 이름을 확인합니다.

   ```powershell
   (Get-ADUser -Filter "sAMAccountName -eq 'aduser7'").userPrincipalName
   (Get-ADUser -Filter "sAMAccountName -eq 'aduser8'").userPrincipalName
   ```

   > **참고**: 확인한 모든 사용자 계정 이름 값을 적어 두세요. 이 랩의 뒷부분에서 계정 이름이 필요합니다.

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 템플릿 기반 배포를 수행하는 데 필요한 토큰 만료 시간을 계산합니다.

   ```powershell
   $((get-date).ToUniversalTime().AddDays(1).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ'))
   ```

   > **참고**: 계산된 값은 `2020-12-27T00:51:28.3008055Z` 형식이어야 합니다. 다음 작업에서 필요하므로 값을 적어 두세요.

   > **참고**: 호스트에 풀 조인 권한을 부여하려면 등록 토큰이 필요합니다. 토큰 만료 날짜 값은 현재 날짜와 시간으로부터 1시간~1개월 범위 내의 값이어야 합니다.

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내에서 Microsoft Edge를 시작하고 [Azure Portal](https://portal.azure.com)로 이동합니다. 메시지가 표시되면 이 랩에서 사용 중인 구독의 Owner 역할이 할당된 사용자 계정의 Azure AD 자격 증명을 사용하여 로그인합니다.
1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 Azure Portal에서 Azure Portal 페이지 상단의 **리소스, 서비스 및 문서 검색** 텍스트 상자를 사용하여 **가상 네트워크**를 검색한 후 해당 위치로 이동합니다. 그런 다음 **가상 네트워크** 블레이드에서 **az140-adds-vnet11**을 선택합니다. 
1. **az140-adds-vnet11** 블레이드에서 **서브넷**을 선택하고 **서브넷**블레이드에서 **+ 서브넷**을 선택합니다. 그런 다음 **서브넷 추가** 블레이드에서 다음 설정을 지정하고(나머지 설정은 모두 기본값으로 유지) **저장을** 클릭합니다.

   |설정|값|
   |---|---|
   |이름|**hp2-Subnet**|
   |서브넷 주소 범위|**10.0.2.0/24**|

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 Azure Portal에서 Azure Portal 페이지 상단의 **리소스, 서비스 및 문서 검색** 텍스트 상자를 사용하여 **네트워크 보안 그룹**을 검색한 후 해당 위치로 이동합니다. 그런 다음 **네트워크 보안 그룹** 블레이드의 **az140-11-RG** 리소스 그룹에서 네트워크 보안 그룹을 선택합니다.
1. 네트워크 보안 그룹 블레이드 왼쪽의 세로 메뉴에 있는 **설정** 섹션에서 **속성**을 클릭합니다.
1. **속성** 블레이드에서 **리소스 ID** 텍스트 상자 오른쪽의 **클립보드에 복사** 아이콘을 클릭합니다. 

   > **참고**: 구독 ID는 구독별로 다르지만 리소스 ID 값은 `/subscriptions/de8279a3-0675-40e6-91e2-5c3728792cb5/resourceGroups/az140-11-RG/providers/Microsoft.Network/networkSecurityGroups/az140-cl-vm11-nsg` 형식이어야 합니다. 다음 작업에서 필요하므로 값을 적어 두세요.

#### 작업 2: Azure Resource Manager 템플릿을 사용하여 Azure Virtual Desktop 호스트 풀 및 호스트 배포

1. 랩 컴퓨터에서 웹 브라우저를 시작하여 [Azure Portal](https://portal.azure.com)로 이동하고 이 랩에서 사용할 구독에서 Owner 역할을 가진 사용자 계정의 자격 증명을 제공하여 로그인합니다.
1. 랩 컴퓨터의 같은 웹 브라우저 창에서 다른 웹 브라우저 탭을 열고 GitHub Azure RDS 템플릿 리포지토리 페이지 [ARM Template to Create and provision new Azure Virtual Desktop hostpool](https://github.com/Azure/RDS-Templates/tree/master/ARM-wvd-templates/CreateAndProvisionHostPool)로 이동합니다. 
1. **ARM Template to Create and provision new Azure Virtual Desktop hostpool** 페이지에서 **Azure에 배포**를 선택합니다. 그러면 브라우저가 Azure Portal의 **사용자 지정 배포** 블레이드로 자동 리디렉션됩니다.
1. **사용자 지정 배포** 블레이드에서 **매개 변수 편집**을 클릭합니다.
1. **매개 변수 편집** 블레이드의 **열기** 대화 상자에서 **파일 로드**을 선택하고 **\\\\AZ-140\\AllFiles\\Labs\\02\\az140-23_azuredeployhp23.parameters.json**을 선택한 후에 **열기**, **저장**을 차례로 선택합니다. 
1. **사용자 지정 배포** 블레이드로 돌아와서 다음 설정을 지정합니다(나머지는 기존 값을 그대로 유지).

   |설정|값|
   |---|---|
   |구독|이 랩에서 사용 중인 Azure 구독의 이름|
   |리소스 그룹|새 리소스 그룹 **az140-23-RG**의 이름|
   |지역|**Azure Virtual Desktop의 배포 준비(AD DS)** 랩에서 AD DS 도메인 컨트롤러를 호스트하는 Azure VM을 배포했던 Azure 지역의 이름|
   |위치|**지역** 매개 변수의 값으로 설정한 지역과 같은 Azure 지역의 이름|
   |작업 영역 위치|**지역** 매개 변수의 값으로 설정한 지역과 같은 Azure 지역의 이름|
   |작업 영역 리소스 그룹|없음. 이 설정을 null로 설정하면 작업 영역 리소스 그룹의 값이 배포 대상 리소스 그룹과 일치하도록 자동 설정됩니다.|
   |모든 애플리케이션 그룹 참조|없음. 대상 작업 영역에 기존 애플리케이션 그룹이 없습니다(작업 영역이 없음).|
   |VM 위치|**위치** 매개 변수의 값으로 설정한 지역과 같은 Azure 지역의 이름|
   |네트워크 보안 그룹 만들기|**false**|
   |네트워크 보안 그룹 ID|이전 작업에서 확인한 기존 네트워크 보안 그룹의 resourceID 매개 변수 값|
   |토큰 만료 시간| 이전 작업에서 계산한 토큰 만료 시간의 값|

   > **참고**: 배포에서는 개인 데스크톱 할당 유형의 풀의 프로비전됩니다.

1. **사용자 지정 배포** 블레이드에서 **검토 + 만들기**를 선택한 다음 **만들기**를 선택합니다.

   > **참고**: 다음 작업을 진행하기 전에 배포가 완료될 때까지 기다립니다. 완료되려면 15분 정도 걸립니다. 

#### 작업 3: Azure Virtual Desktop 호스트 풀 및 호스트 배포 확인

1. 랩 컴퓨터의 Azure Portal이 표시된 웹 브라우저에서 **Azure Virtual Desktop**을 검색하여 선택한 후 **Azure Virtual Desktop** 블레이드에서 **호스트 풀**을 선택합니다. 그런 다음 **Azure Virtual Desktop \| 호스트 풀** 블레이드에서 새로 배포된 풀에 해당하는 **az140-23-hp2** 항목을 선택합니다.
1. **az140-23-hp2** 블레이드 왼쪽의 세로 메뉴에 있는 **관리** 섹션에서 **세션 호스트**를 클릭합니다. 
1. **az140-23-hp2 \| 세션 호스트** 블레이드에서 배포에 호스트 2개가 포함되어 있는지 확인합니다.
1. **az140-23-hp2 \| 세션 호스트** 블레이드 왼쪽의 세로 메뉴에 있는 **관리** 섹션에서 **애플리케이션 그룹**을 클릭합니다.
1. **az140-23-hp2 \| 애플리케이션 그룹** 블레이드에서 배포에 **Default Desktop** 애플리케이션 그룹 **az140-23-hp2-DAG**가 포함되어 있는지 확인합니다.

#### 작업 4: Azure Resource Manager 템플릿을 사용하여 기존 Azure Virtual Desktop 호스트 풀에 호스트를 추가하는 작업 준비

1. 랩 컴퓨터에서 **az140-dc-vm11**에 연결된 원격 데스크톱 세션으로 전환합니다. 
1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 이 연습의 앞부분에서 프로비전한 풀에 새 호스트를 조인하는 데 필요한 토큰을 생성합니다.

   ```powershell
   $registrationInfo = New-AzWvdRegistrationInfo -ResourceGroupName 'az140-23-RG' -HostPoolName 'az140-23-hp2' -ExpirationTime $((get-date).ToUniversalTime().AddDays(1).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ'))
   ```

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 토큰 값을 검색한 후 클립보드에 붙여넣습니다.

   ```powershell
   $registrationInfo.Token | clip
   ```

   > **참고**: 다음 작업에서 필요하므로 클립보드에 복사한 값을 적어 둡니다(예: 메모장을 시작하고 Ctrl+V 키 조합을 눌러 클립보드의 내용을 메모장에 붙여넣기). 줄 바꿈이 없는 한 줄로 된 텍스트만 포함된 값을 사용해야 합니다. 

   > **참고**: 호스트에 풀 조인 권한을 부여하려면 등록 토큰이 필요합니다. 토큰 만료 날짜 값은 현재 날짜와 시간으로부터 1시간~1개월 범위 내의 값이어야 합니다.

#### 작업 5: Azure Resource Manager 템플릿을 사용하여 기존 Azure Virtual Desktop 호스트 풀에 호스트 추가

1. 랩 컴퓨터의 같은 웹 브라우저 창에서 다른 웹 브라우저 탭을 열고 GitHub Azure RDS 템플릿 리포지토리 페이지 [ARM Template to Add sessionhosts to an existing Azure Virtual Desktop hostpool](https://github.com/Azure/RDS-Templates/tree/master/ARM-wvd-templates/AddVirtualMachinesToHostPool)로 이동합니다. 
1. **ARM Template to Add sessionhosts to an existing Azure Virtual Desktop hostpool** 페이지에서 **Azure에 배포**를 선택합니다. 그러면 브라우저가 Azure Portal의 **사용자 지정 배포** 블레이드로 자동 리디렉션됩니다.
1. **사용자 지정 배포** 블레이드에서 **매개 변수 편집**을 클릭합니다.
1. **매개 변수 편집** 블레이드의 **열기** 대화 상자에서 **파일 로드**을 선택하고 **\\\\AZ-140\\AllFiles\\Labs\\02\\az140-23_azuremodifyhp23.parameters.json**을 선택한 후에 **열기**, **저장**을 차례로 선택합니다. 
1. **사용자 지정 배포** 블레이드로 돌아와서 다음 설정을 지정합니다(나머지는 기존 값을 그대로 유지).

   |설정|값|
   |---|---|
   |구독|이 랩에서 사용 중인 Azure 구독의 이름|
   |리소스 그룹|**az140-23-RG**|
   |호스트 풀 토큰|이전 작업에서 생성한 토큰의 값|
   |호스트 풀 위치|이 랩의 앞부분에서 호스트 풀을 배포한 Azure 지역의 이름|
   |VM 관리자 계정 사용자 이름:|**student**|
   |VM 관리자 계정 암호|**Pa55w.rd1234**|
   |VM 위치|**호스트 풀 위치** 매개 변수의 값으로 설정한 지역과 같은 Azure 지역의 이름|
   |네트워크 보안 그룹 만들기|**false**|
   |네트워크 보안 그룹 ID|이전 작업에서 확인한 기존 네트워크 보안 그룹의 resourceID 매개 변수 값|

1. **사용자 지정 배포** 블레이드에서 **검토 + 만들기**를 선택한 다음 **만들기**를 선택합니다.

   > **참고**: 다음 작업을 진행하기 전에 배포가 완료될 때까지 기다립니다. 5분 정도 걸릴 수 있습니다.

#### 작업 6: Azure Virtual Desktop 호스트 풀의 변경 내용 확인

1. 랩 컴퓨터의 Azure Portal이 표시된 웹 브라우저에서 **가상 머신**을 검색하여 선택하고 **가상 머신** 블레이드에서 목록에 추가 가상 머신 **az140-23-p2-2**가 포함되어 있는지 확인합니다.
1. 랩 컴퓨터에서 **az140-dc-vm11**에 연결된 원격 데스크톱 세션으로 전환합니다. 
1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 세 번째 호스트가 **adatum.com** AD DS 도메인에 정상적으로 조인되었는지 확인합니다.

   ```powershell
   Get-ADComputer -Filter "sAMAccountName -eq 'az140-23-p2-2$'"
   ```
1. 랩 컴퓨터로 돌아간 후 Azure Portal이 표시된 웹 브라우저에서 **Azure Virtual Desktop**을 검색하여 선택한 후 **Azure Virtual Desktop** 블레이드에서 **호스트 풀**을 선택합니다. 그런 다음 **Azure Virtual Desktop \| 호스트 풀** 블레이드에서 새로 수정된 풀에 해당하는 **az140-23-hp2** 항목을 선택합니다.
1. **az140-23-hp2** 블레이드에서 **필수** 섹션을 검토하여 **호스트 풀 유형**이 **개인**으로, **할당 유형** 이 **자동**으로 설정되어 있는지 확인합니다.
1. **az140-23-hp2** 블레이드 왼쪽의 세로 메뉴에 있는 **관리** 섹션에서 **세션 호스트**를 클릭합니다. 
1. **az140-23-hp2 \| 세션 호스트** 블레이드에서 배포에 호스트 3개가 포함되어 있는지 확인합니다. 

#### 작업 7: Azure Virtual Desktop 호스트 풀에서 개인 데스크톱 할당 관리

1. 랩 컴퓨터에서 Azure Portal이 표시된 웹 브라우저 내 **az140-23-hp2 \| 세션 호스트** 블레이드 왼쪽의 세로 메뉴에 있는 **관리** 섹션에서 **애플리케이션 그룹**을 선택합니다. 
1. **az140-23-hp2 \| 애플리케이션 그룹** 블레이드의 애플리케이션 그룹 목록에서 **az140-23-hp2-DAG**를 선택합니다.
1. **az140-23-hp2-DAG** 블레이드 왼쪽의 세로 메뉴에서 **할당**을 선택합니다. 
1. **az140-23-hp2-DAG \| 할당** 블레이드에서 **+ 추가**를 선택합니다.
1. **Azure AD 사용자 또는 사용자 그룹 선택** 블레이드에서 **az140-wvd-personal**을 선택하고 **선택**을 클릭합니다.

   > **참고**: 이제 Azure Virtual Desktop 호스트 풀에 연결하는 사용자의 환경을 검토해 보겠습니다.

1. 랩 컴퓨터의 Azure Portal이 표시된 브라우저 창에서 **가상 머신**을 검색하여 선택합니다. 그런 다음 **가상 머신** 블레이드에서 **az140-cl-vm11** 항목을 선택합니다.
1. **az140-cl-vm11** 블레이드에서 **연결**을 선택하고 드롭다운 메뉴에서 **Bastion**을 선택합니다. 그런 다음 **az140-cl-vm11 \| 연결** 블레이드의 **Bastion** 탭에서 **Bastion 사용**을 선택합니다.
1. 메시지가 표시되면 다음 자격 증명을 제공하고 **연결**을 선택합니다.

   |설정|값|
   |---|---|
   |사용자 이름|**Student@adatum.com**|
   |암호|**Pa55w.rd1234**|

1. **az140-cl-vm11**에 연결된 원격 데스크톱 세션 내에서 **시작**을 클릭하고 **시작** 메뉴에서 **Remote Desktop** 클라이언트 앱을 선택합니다.
1. **Remote Desktop** 클라이언트 창에서 **Subscribe**를 선택하고 메시지가 표시되면 **aduser7** 자격 증명으로 로그인합니다. 로그인할 때는 userPrincipalName, 그리고 이 계정을 만들 때 설정한 암호를 입력합니다.

   > **참고**: Subscribe 옵션 대신 **Remote Desktop** 클라이언트 창에서 **Subscribe with URL**을 선택할 수도 있습니다. 그러면 표시되는 **Subscribe to a Workspace** 창의 **Email or Workspace URL**에 **https://rdweb.wvd.microsoft.com/api/arm/feeddiscovery** 를 입력하고 **Next**를 선택합니다. 메시지가 표시되면 **aduser7** 자격 증명으로 로그인합니다(사용자 이름으로는 userPrincipalName 특성을 사용하고 암호로는 이 계정을 만들 때 설정한 암호 사용). 

1. **Remote Desktop** 페이지에서 **SessionDesktop** 아이콘을 두 번 클릭합니다. 자격 증명을 입력하라는 메시지가 표시되면 같은 암호를 다시 입력하고 **Remember me** 체크박스를 선택한 후에 **OK**를 클릭합니다.
1. **Stay signed in to all your apps** 창에서 **Allow my organization to manage my device** 체크박스 선택을 취소하고 **No, sign in to this app only**를 선택합니다. 
1. **aduser7**이 Remote Desktop을 통해 호스트에 정상적으로 로그인했는지 확인합니다.
1. **aduser7**로 호스트 중 하나에 연결한 원격 데스크톱 세션 내에서 **시작**을 마우스 오른쪽 단추로 클릭하고 오른쪽 클릭 메뉴에서 **종료 또는 로그아웃**을 선택합니다. 그런 다음 계단식 메뉴에서 **로그아웃**을 클릭합니다.

   > **참고**: 이번에는 개인 데스크톱 할당을 직접 모드에서 자동으로 전환해 보겠습니다. 

1. 랩 컴퓨터로 전환하여 Azure Portal이 표시된 웹 브라우저 내 **az140-23-hp2-DAG \| 할당** 블레이드의 할당 목록 바로 위에 있는 알림 표시줄에서 **VM 할당** 링크를 클릭합니다. 그러면 **az140-23-hp2 \| 세션 호스트** 블레이드로 리디렉션됩니다. 
1. **az140-23-hp2 \| 세션 호스트** 블레이드에서 호스트 중 하나의 **할당된 사용자** 열 목록에 **aduser7**이 표시되어 있는지 확인합니다.

   > **참고**: 호스트 풀이 자동 할당 방식으로 구성되어 있으므로 aduser7이 할당된 사용자로 표시됩니다.

1. 랩 컴퓨터의 Azure Portal이 표시된 웹 브라우저 창에서 **Cloud Shell** 창 내에 **PowerShell** 셸 세션을 엽니다.
1. Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 직접 할당 모드로 전환합니다.

    ```powershell
    Update-AzWvdHostPool -ResourceGroupName 'az140-23-RG' -Name 'az140-23-hp2' -PersonalDesktopAssignmentType Direct
    ```

1. 랩 컴퓨터의 Azure Portal이 표시된 웹 브라우저 창에서 **az140-23-hp2** 호스트 풀 블레이드로 이동합니다. 그런 다음 **필수** 섹션을 검토하여 **호스트 풀 유형**이 **개인**으로, **할당 유형**이 **직접**으로 설정되어 있는지 확인합니다.
1. **az140-cl-vm11**에 연결된 원격 데스크톱 세션으로 다시 전환하여 **원격 데스크톱** 창 오른쪽 위에 있는 줄임표 아이콘을 클릭합니다. 그런 다음 드롭다운 메뉴에서 **Unsubscribe**를 클릭하고 확인하라는 메시지가 표시되면 **Continue**를 클릭합니다.
1. **az140-cl-vm11**에 연결된 원격 데스크톱 세션 내의 **Remote Desktop** 창 **Let's get started** 페이지에서 **Subscribe**를 선택합니다.
1. 로그인하라는 메시지가 표시되면 **Pick an account** 페이지에서 **Use another account**를 클릭합니다. 그런 후에 메시지가 표시되면 **aduser8** 사용자 계정의 사용자 계정 이름과 이 계정을 만들 때 설정한 암호를 사용하여 로그인합니다.
1. **Stay signed in to all your apps** 창에서 **Allow my organization to manage my device** 체크박스 선택을 취소하고 **No, sign in to this app only**를 선택합니다. 
1. **Remote Desktop** 페이지에서 **SessionDesktop** 아이콘을 두 번 클릭하고 **We couldn't connect because there are currently no available resources. Try again later or contact tech support for help if this keeps happening** 오류 메시지가 표시됨을 확인한 후에 **OK**를 클릭합니다.

   > **참고**: 호스트 풀이 직접 할당 방식으로 구성되어 있는데 **aduser8**에는 호스트가 할당되지 않았으므로 이 오류 메시지가 표시되는 것은 정상적인 현상입니다.

1. 랩 컴퓨터로 전환하여 Azure Portal이 표시된 웹 브라우저 내 **az140-23-hp2 \| 세션 호스트** 블레이드에서 남아 있는 미할당 호스트 2개 중 하나의 옆에 있는 **할당된 사용자** 열에서 **(할당)** 링크를 선택합니다.
1. **사용자 할당**에서 **aduser8**을 선택하고 **선택**을 클릭한 후 할당을 확인하라는 메시지가 표시되면 **확인**을 클릭합니다.
1. **az140-cl-vm11**에 연결된 원격 데스크톱 세션으로 다시 전환하여 **Remote Desktop** 창에서 **SessionDesktop** 아이콘을 두 번 클릭합니다. 암호를 입력하라는 메시지가 표시되면 이 사용자 계정을 만들 때 설정한 암호를 입력하고 **OK**를 클릭하여 할당된 호스트에 정상적으로 로그인할 수 있는지 확인합니다.

### 연습 2: 랩에서 프로비전한 Azure VM 중지 및 할당 취소

이 연습의 주요 작업은 다음과 같습니다.

1. 랩에서 프로비전한 Azure VM 중지 및 할당 취소

>**참고**: 이 연습에서는 해당 컴퓨팅 비용을 최소화하기 위해 이 랩에서 프로비전한 Azure VM의 할당을 취소합니다.

#### 작업 1: 랩에서 프로비전한 Azure VM 할당 취소

1. 랩 컴퓨터로 전환한 다음 Azure Portal이 표시된 웹 브라우저 창에서 **Cloud Shell** 창 내에 **PowerShell** 셸 세션을 엽니다.
1. Cloud Shell 창 내의 PowerShell 세션에서 다음 명령을 실행하여 이 랩에서 만든 모든 Azure VM의 목록을 표시합니다.

   ```powershell
   Get-AzVM -ResourceGroup 'az140-23-RG'
   ```

1. Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 이 랩에서 만든 모든 Azure VM을 중지하고 할당을 취소합니다.

   ```powershell
   Get-AzVM -ResourceGroup 'az140-23-RG' | Stop-AzVM -NoWait -Force
   ```

   >**참고**: 명령은 비동기적으로 실행되므로(-NoWait 매개 변수에 의해 결정됨) 동일한 PowerShell 세션 내에서 즉시 다른 PowerShell 명령을 실행할 수는 있지만, Azure VM이 실제로 중지 및 할당 취소되려면 몇 분 정도 걸립니다.
