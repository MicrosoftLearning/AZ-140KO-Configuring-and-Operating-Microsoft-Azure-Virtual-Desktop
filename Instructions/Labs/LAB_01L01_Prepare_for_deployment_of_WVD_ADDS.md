﻿---
lab:
    title: '랩: Azure Windows Virtual Desktop의 배포 준비(AD DS)'
    module: '모듈 1: WVD 아키텍처 계획'
---

# 랩 - Azure Windows Virtual Desktop의 배포 준비(AD DS)
# 학생 랩 매뉴얼

## 랩 종속성

- 이 랩에서 사용할 Azure 구독
- 이 랩에서 사용할 Azure 구독에 대한 소유자 또는 참가자 역할, 그리고 해당 Azure 구독에 연결된 Azure AD 테넌트의 전역 관리자 역할이 할당되어 있는 Microsoft 계정 또는 Azure AD 계정

> **참고**: 이 과정 작성 시점에 Windows Virtual Desktop용 MSIX 앱 연결 기능은 공개 미리 보기 상태입니다. 이 과정에 포함된 MSIX 앱 연결 기능을 사용하는 랩을 실행하려는 경우에는 [온라인 양식](https://aka.ms/enablemsixappattach)을 통해 요청을 제출하여 구독에서 MSIX 앱 연결을 사용하도록 설정해야 합니다. 요청 승인과 처리는 영업일 기준으로 최대 24시간이 걸릴 수 있습니다. 요청이 수락되어 처리가 완료되면 확인 이메일이 수신됩니다.

## 예상 소요 시간

60분

>**참고**: Azure AD DS 프로비전 시의 대기 시간은 약 90분입니다.

## 랩 시나리오

Active Directory Domain Services(AD DS) 환경에서 Azure Windows Virtual Desktop 배포를 준비해야 합니다.

## 목표
  
이 랩을 완료하면 다음을 수행할 수 있습니다.

- Azure VM을 사용하여 Active Directory Domain Services(AD DS) 단일 도메인 포리스트 배포
- Azure AD 포리스트와 Azure active Directory(Azure AD) 테넌트 통합

## 랩 파일

-  \\\\AZ-140\\AllFiles\\Labs\\01\\az140-11_azuredeploydc11.parameters.json
-  \\\\AZ-140\\AllFiles\\Labs\\01\\az140-11_azuredeploycl11.json
-  \\\\AZ-140\\AllFiles\\Labs\\01\\az140-11_azuredeploycl11.parameters.json

## 지침

### 연습 0: vCPU 할당량 늘리기

이 연습의 기본 작업은 다음과 같습니다.

1. 현재 vCPU 사용량 파악
1. vCPU 할당량 늘리기 요청

#### 작업 1: 현재 vCPU 사용량 파악

1. 랩 컴퓨터에서 웹 브라우저를 시작하고 [Azure Portal](https://portal.azure.com)로 이동합니다. 그런 다음 이 랩에서 사용할 구독의 소유자 역할이 할당된 사용자 계정의 자격 증명을 입력하여 로그인합니다.
1. Azure Portal에서 검색 텍스트 상자 바로 오른쪽의 도구 모음 아이콘을 선택하여 **Cloud Shell** 창을 엽니다.
1. **Bash** 또는 **PowerShell**을 선택하라는 메시지가 표시되면 **PowerShell**을 선택합니다. 

   >**참고**: **Cloud Shell**을 처음 시작할 때 **탑재된 스토리지가 없음** 메시지가 표시되면 이 랩에서 사용하는 구독을 선택하고 **스토리지 만들기**를 선택합니다. 

1. Azure Portal의 **Cloud Shell** PowerShell 세션에서 다음 명령을 실행하여 현재 vCPU 사용량, 그리고 **StandardDSv3Family** 및 **StandardBSFamily** Azure VM의 vCPU 사용량 한도를 확인합니다(`<Azure_region>` 자리 표시자는 `eastus` 등 이 랩에서 사용하려는 Azure 지역의 이름으로 바꿔야 함).

   ```powershell
   $location = '<Azure_region>'
   Get-AzVMUsage -Location $location | Where-Object {$_.Name.Value -eq 'StandardDSv3Family'}
   ```

   > **참고**: Azure 지역의 이름을 확인하려면 **Cloud Shell**의 PowerShell 프롬프트에서 `(Get-AzLocation).Location`을 실행합니다.
   
1. 이전 단계에서 실행한 명령 출력을 검토하여 대상 Azure 지역에서 Azure VM의 **Standard DSv3 Family** 및 **StandardBDFamily** 둘 다에서 사용 가능한 vCPU가 **20**개 이상인지 확인합니다. 사용 가능한 vCPU가 20개 이상인 경우에는 다음 연습부터 바로 진행하면 됩니다. 그렇지 않은 경우에는 이 연습의 다음 작업을 계속 진행합니다. 

#### 작업 2: vCPU 할당량 늘리기 요청

1. Azure Portal에서 **구독**을 검색하여 선택하고 **구독** 블레이드에서 이 랩에 사용할 Azure 구독에 해당하는 항목을 선택합니다.
1. Azure Portal의 구독 블레이드 왼쪽 세로 메뉴에 있는 설정 섹션에서 사용량 및 할당량을 선택합니다. 
1. 구독의 **사용량 및 할당량** 블레이드에서 **증가 요청**을 선택합니다.
1. **새 지원 요청** 블레이드의 **기본** 탭에서 다음 항목을 지정하고 **다음: 솔루션 >**을 선택합니다.

   |설정|값|
   |---|---|
   |문제 유형|**서비스 및 구독 제한(할당량)**|
   |구독|이 랩에서 사용할 Azure 구독의 이름|
   |할당량 유형|**계산-VM(코어-vCPU) 구독 제한 늘리기**|
   |지원 계획|대상 구독과 연결된 지원 계획의 이름|

1. **새 지원 요청** 블레이드의 **세부 정보** 탭에서 **세부 정보 제공** 링크를 선택합니다.
1. **새 지원 요청** 블레이드의 **할당량 정보** 탭에서 다음 항목을 지정하고 **저장 및 계속**을 선택합니다.

   |설정|값|
   |---|---|
   |배포 모델|**Resource Manager**|
   |위치|이 랩에서 사용할 Azure 지역의 이름|
   |유형|**Standard**|
   |표준|**BS Series**|
   |새 vCPU 한도|새 한도|
   |표준|**DSv3 Series**|
   |새 vCPU 한도|새 한도|

   >**참고**: 여기서는 랩 환경 실행 비용을 최소화하기 위해 **BS Series** Azure VM을 사용합니다. 하지만 Windows Virtual Desktop 시나리오에서 반드시 **BS Series** Azure VM을 사용해야 하는 것은 아닙니다.

1. **새 지원 요청** 블레이드의 **세부 정보** 탭으로 돌아와 다음 항목을 지정하고 **다음: 검토 + 만들기 >**를 선택합니다.

   |설정|값|
   |---|---|
   |심각도|**C - 최소 영향**|
   |기본 연락 방법|원하는 옵션을 선택하고 연락처 세부 정보 입력|
    
1. **새 지원 요청** 블레이드의 **검토 + 만들기** 탭에서 **만들기**를 선택합니다.

   > **참고**: 이 vCPU 범위 내의 할당량 늘리기 요청은 대개 몇 시간 내에 완료됩니다.

### 연습 1: Active Directory Domain Services(AD DS) 도메인 배포

이 연습의 기본 작업은 다음과 같습니다.

1. Azure VM 배포에 사용할 수 있는 DNS 이름 식별
1. Azure Resource Manager 빠른 시작 템플릿을 사용하여 AD DS 도메인 컨트롤러를 실행하는 Azure VM 배포
1. Azure Resource Manager 빠른 시작 템플릿을 사용하여 Windows 10을 실행하는 Azure VM 배포

#### 작업 1: Azure VM 배포에 사용할 수 있는 DNS 이름 식별

1. 랩 컴퓨터에서 웹 브라우저를 시작하고 [Azure Portal](https://portal.azure.com)로 이동합니다. 그런 다음 이 랩에서 사용할 구독의 소유자 역할이 할당된 사용자 계정의 자격 증명을 입력하여 로그인합니다.
1. Azure Portal에서 검색 텍스트 상자의 오른쪽에 있는 도구 모음 아이콘을 직접 선택하여 **Cloud Shell** 창을 엽니다.
1. **Bash** 또는 **PowerShell**을 선택하라는 메시지가 표시되면 **PowerShell**을 선택합니다. 

   >**참고**: **Cloud Shell**을 처음 시작할 때 **탑재된 스토리지가 없음** 메시지가 표시되면 이 랩에서 사용하는 구독을 선택하고 **스토리지 만들기**를 선택합니다. 

1. Cloud Shell 창에서 다음 명령을 실행하여 다음 작업에서 입력해야 하는 사용 가능한 DNS 이름을 확인합니다(`<custom-label>` 자리 표시자는 유효한 DNS 도메인 이름 접미사(전역적으로 고유한 접미사일 가능성이 높음)로 대체, `<Azure_region>` 자리 표시자는 Active Directory 도메인 컨트롤러를 호스트할 Azure VM을 배포하려는 Azure 지역 이름으로 대체).

   ```powershell
   $location = '<Azure_region>'
   Test-AzDnsAvailability -Location $location -DomainNameLabel <custom-name>
   ```
   > **참고**: Azure VM을 프로비전할 수 있는 Azure 지역을 식별하려면 [https://azure.microsoft.com/en-us/regions/offers/](https://azure.microsoft.com/en-us/regions/offers/)를 참고하세요.

1. 이 명령이 **True**를 반환하는지 확인합니다. True가 반환되지 않으면 **True**가 반환될 때까지 `<custom-name>`의 다른 값을 사용해 같은 명령을 다시 실행합니다.
1. 그리고 True를 반환한 `<custom-name>`의 값을 적어 둡니다. 다음 작업에서 해당 값이 필요합니다.

#### 작업 2: Azure Resource Manager 빠른 시작 템플릿을 사용하여 AD DS 도메인 컨트롤러를 실행하는 Azure VM 배포

1. 랩 컴퓨터의 Azure Portal이 표시된 웹 브라우저 내 Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 리소스 그룹을 만듭니다.

   ```powershell
   $resourceGroupName = 'az140-11-RG'
   New-AzResourceGroup -Location $location -Name $resourceGroupName
   ```

1. Azure Portal에서 **Cloud Shell** 창을 닫습니다.
1. 랩 컴퓨터의 같은 웹 브라우저 창에서 다른 웹 브라우저 탭을 열고 [새 Windows VM 만들기 및 새 AD 포리스트, 도메인 및 DC 만들기](https://github.com/Azure/azure-quickstart-templates/tree/master/active-directory-new-domain) 빠른 시작 템플릿으로 이동합니다. 
1. **새 Windows VM 만들기에서 새 AD 포리스트, 도메인 및 DC 만들기** 페이지에서 **Azure에 배포**를 선택합니다. 이렇게 하면 Azure Portal의 **새 AD 포리스트로 Azure VM 만들기** 블레이드로 브라우저가 자동으로 리디렉션됩니다.
1. **새 AD 포리스트로 Azure VM 만들기** 블레이드에서 **매개 변수 편집**을 선택합니다.
1. **매개 변수 편집** 블레이드의 **열기** 대화 상자에서 **파일 로드**을 선택하고 **\\\\AZ-140\\AllFiles\\Labs\\01\\az140-11_azuredeploydc11.parameters.json**을 선택한 후에 **열기**, **저장**을 차례로 선택합니다. 
1. **새 AD 포리스트를 사용하여 Azure VM 만들기** 블레이드에서 다음 설정을 지정합니다(나머지는 기존 값을 그대로 유지).

   |설정|값|
   |---|---|
   |구독|이 랩에서 사용 중인 Azure 구독의 이름|
   |리소스 그룹|**az140-11-RG**|
   |도메인 이름|**adatum.com**|
   |DNS 접두사|이전 작업에서 확인한 DNS 호스트 이름|

1. **새 AD 포리스트를 사용하여 Azure VM 만들기** 블레이드에서 **검토 + 만들기**, **만들기**를 차례로 선택합니다.

   > **참고**: 배포가 완료될 때까지 기다린 후 다음 연습을 진행합니다. 완료되려면 15분 정도 걸립니다. 

#### 작업 3: Azure Resource Manager 빠른 시작 템플릿을 사용하여 Windows 10을 실행하는 Azure VM 배포

1. 랩 컴퓨터에서 Azure Portal이 표시된 웹브라우저 내 Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 이전 작업에서 만든 **az140-adds-vnet11** 가상 네트워크에 서브넷 **cl-Subnet**을 추가합니다.

   ```powershell
   $resourceGroupName = 'az140-11-RG'
   $vnet = Get-AzVirtualNetwork -ResourceGroupName $resourceGroupName -Name 'az140-adds-vnet11'
   $subnetConfig = Add-AzVirtualNetworkSubnetConfig `
     -Name 'cl-Subnet' `
     -AddressPrefix 10.0.255.0/24 `
     -VirtualNetwork $vnet
   $vnet | Set-AzVirtualNetwork
   ```

1. Azure Portal의 Cloud Shell 창 도구 모음에서 **파일 업로드/다운로드** 아이콘을 선택하고 드롭다운 메뉴에서 **업로드**를 선택합니다. 그런 다음 **\\\\AZ-140\\AllFiles\\Labs\\01\\az140-11_azuredeploycl11.json** 및 **\\\\AZ-140\\AllFiles\\Labs\\01\\az140-11_azuredeploycl11.parameters.json** 파일을 Cloud Shell 홈 디렉터리에 업로드합니다.
1. Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 Windows 10을 실행하는 Azure VM을 배포합니다. 이 VM은 새로 만든 서브넷의 Windows Virtual Desktop 클라이언트로 사용됩니다.

   ```powershell
   $location = (Get-AzResourceGroup -ResourceGroupName $resourceGroupName).Location
   New-AzResourceGroupDeployment `
     -ResourceGroupName $resourceGroupName `
     -Location $location `
     -Name az140lab0101vmDeployment `
     -TemplateFile $HOME/az140-11_azuredeploycl11.json `
     -TemplateParameterFile $HOME/az140-11_azuredeploycl11.parameters.json
   ```

   > **참고**: 배포가 완료될 때까지 기다리지 말고 다음 연습을 진행하세요. 배포는 10분 정도 걸릴 수 있습니다.


### 연습 2: Azure AD 포리스트와 Azure AD 테넌트 통합
  
이 연습의 기본 작업은 다음과 같습니다.

1. Azure AD에 동기화할 AD DS 사용자 및 그룹 만들기
1. AD DS UPN 접미사 구성
1. Azure AD와의 동기화를 구성하는 데 사용할 Azure AD 사용자 만들기
1. Azure AD Connect 설치
1. 하이브리드 Azure AD 조인 구성

#### 작업 1: Azure AD에 동기화할 AD DS 사용자 및 그룹 만들기

1. 랩 컴퓨터의 Azure Portal이 표시된 웹 브라우저에서 **가상 머신**을 검색하여 선택하고 **가상 머신** 블레이드에서 **az140-dc-vm11**을 선택합니다.
1. **az140-dc-vm11** 블레이드에서 **연결**을 선택하고 드롭다운 메뉴에서 **RDP**를 선택합니다. 그런 다음 **az140-dc-vm11 \** **연결** 블레이드의**| 연결** 블레이드의 **IP 주소** 드롭다운 목록에서 **부하 분산 장치 DNS 이름** 항목을 선택한 다음 **RDP 파일 다운로드**를 선택합니다.
1. 메시지가 표시되면 다음 자격 증명으로 로그인합니다.

   |설정|값|
   |---|---|
   |사용자 이름|**ADATUM\\Student**|
   |암호|**Pa55w.rd1234**|

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내에서 **Windows PowerShell ISE**를 관리자 권한으로 시작합니다.
1. **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 Internet Explorer 관리자용 보안 강화를 사용하지 않도록 설정합니다.

   ```powershell
   $adminRegEntry = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}'
   Set-ItemProperty -Path $AdminRegEntry -Name 'IsInstalled' -Value 0
   Stop-Process -Name Explorer
   ```

1. **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 AD DS 조직 구성 단위를 만듭니다. 이 조직 구성 단위에는 이 랩에서 사용하는 Azure AD 테넌트로의 동기화 범위 내 개체가 포함됩니다.

   ```powershell
   New-ADOrganizationalUnit 'ToSync' 朴ath 'DC=adatum,DC=com' -ProtectedFromAccidentalDeletion $false
   ```

1. **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 AD DS 조직 구성 단위를 만듭니다. 이 조직 구성 단위에는 Windows 10 도메인 조인 클라이언트 컴퓨터의 컴퓨터 개체가 포함됩니다.

   ```powershell
   New-ADOrganizationalUnit 'WVDClients' 朴ath 'DC=adatum,DC=com' -ProtectedFromAccidentalDeletion $false
   ```

1. **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 AD DS 사용자 계정을 만듭니다. 이 계정은 이 랩에서 사용하는 Azure AD 테넌트에 동기화됩니다.

   ```powershell
   $ouName = 'ToSync'
   $ouPath = "OU=$ouName,DC=adatum,DC=com"
   $adUserNamePrefix = 'aduser'
   $adUPNSuffix = 'adatum.com'
   $userCount = 1..9
   foreach ($counter in $userCount) {
     New-AdUser -Name $adUserNamePrefix$counter -Path $ouPath -Enabled $True `
       -ChangePasswordAtLogon $false -userPrincipalName $adUserNamePrefix$counter@$adUPNSuffix `
       -AccountPassword (ConvertTo-SecureString 'Pa55w.rd1234' -AsPlainText -Force) -passThru
   } 

   $adUserNamePrefix = 'wvdadmin1'
   $adUPNSuffix = 'adatum.com'
   New-AdUser -Name $adUserNamePrefix -Path $ouPath -Enabled $True `
       -ChangePasswordAtLogon $false -userPrincipalName $adUserNamePrefix@$adUPNSuffix `
       -AccountPassword (ConvertTo-SecureString 'Pa55w.rd1234' -AsPlainText -Force) -passThru

   Get-ADGroup -Identity 'Domain Admins' | Add-AdGroupMember -Members 'wvdadmin1'
   ```

   > **참고**: 이 스크립트는 권한이 없는 사용자 계정 9개(**aduser1** - **aduser9**), 그리고 **ADATUM\\Domain Admins** 그룹 구성원인 권한이 있는 계정 1개(**wvdadmin1**)를 만듭니다.

1. **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 AD DS 그룹 개체를 만듭니다. 이 개체는 이 랩에서 사용하는 Azure AD 테넌트에 동기화됩니다.

   ```powershell
   New-ADGroup -Name 'az140-wvd-pooled' -GroupScope 'Global' -GroupCategory Security -Path $ouPath
   New-ADGroup -Name 'az140-wvd-remote-app' -GroupScope 'Global' -GroupCategory Security -Path $ouPath
   New-ADGroup -Name 'az140-wvd-personal' -GroupScope 'Global' -GroupCategory Security -Path $ouPath
   New-ADGroup -Name 'az140-wvd-users' -GroupScope 'Global' -GroupCategory Security -Path $ouPath
   New-ADGroup -Name 'az140-wvd-admins' -GroupScope 'Global' -GroupCategory Security -Path $ouPath
   ```

1. **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 이전 단계에서 만든 그룹에 구성원을 추가합니다.

   ```powershell
   Get-ADGroup -Identity 'az140-wvd-pooled' | Add-AdGroupMember -Members 'aduser1','aduser2','aduser3','aduser4'
   Get-ADGroup -Identity 'az140-wvd-remote-app' | Add-AdGroupMember -Members 'aduser1','aduser5','aduser6'
   Get-ADGroup -Identity 'az140-wvd-personal' | Add-AdGroupMember -Members 'aduser7','aduser8','aduser9'
   Get-ADGroup -Identity 'az140-wvd-users' | Add-AdGroupMember -Members 'aduser1','aduser2','aduser3','aduser4','aduser5','aduser6','aduser7','aduser8','aduser9'
   Get-ADGroup -Identity 'az140-wvd-admins' | Add-AdGroupMember -Members 'wvdadmin1'
   ```

#### 작업 2: AD DS UPN 접미사 구성

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 PowerShellGet 모듈의 최신 버전을 설치합니다(설치를 확인하라는 메시지가 표시되면 **예** 선택).

   ```powershell
   [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
   Install-Module -Name PowerShellGet -Force -SkipPublisherCheck
   ```

1. **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 Az PowerShell 모듈의 최신 버전을 설치합니다(설치를 확인하라는 메시지가 표시되면 **모두 예** 선택).

   ```powershell
   Install-Module -Name Az -AllowClobber -SkipPublisherCheck
   ```

1. **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 Azure 구독에 로그인합니다.

   ```powershell
   Connect-AzAccount
   ```

1. 메시지가 표시되면 이 랩에서 사용 중인 구독의 소유자 역할이 할당된 사용자 계정의 자격 증명을 입력합니다.
1. **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 Azure 구독과 연결된 Azure AD 테넌트의 Id 속성을 검색합니다.

   ```powershell
   $tenantId = (Get-AzContext).Tenant.Id
   ```

1. **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 Azure AD PowerSHell 모듈의 최신 버전을 설치합니다.

   ```powershell
   Install-Module -Name AzureAD -Force
   ```

1. **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 Azure AD 테넌트에 인증합니다.

   ```powershell
   Connect-AzureAD -TenantId $tenantId
   ```

1. 메시지가 표시되면 이 작업 앞부분에서 사용한 것과 같은 자격 증명으로 로그인합니다. 
1. **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 Azure 구독과 연결된 Azure AD 테넌트의 기본 DNS 도메인 이름을 검색합니다.

   ```powershell
   $aadDomainName = ((Get-AzureAdTenantDetail).VerifiedDomains)[0].Name
   ```

1. **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 Azure 구독과 연결된 Azure AD 테넌트의 기본 DNS 도메인 이름을 AD DS 포리스트의 UPN 접미사 목록에 추가합니다.

   ```powershell
   Get-ADForest|Set-ADForest -UPNSuffixes @{add="$aadDomainName"}
   ```

1. **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 Azure 구독과 연결된 Azure AD 테넌트의 기본 DNS 도메인 이름을 AD DS 도메인 내 모든 사용자의 UPN 접미사로 할당합니다.

   ```powershell
   $domainUsers = Get-ADUser -Filter {UserPrincipalName -like '*adatum.com'} -Properties userPrincipalName -ResultSetSize $null
   $domainUsers | foreach {$newUpn = $_.UserPrincipalName.Replace('adatum.com',$aadDomainName); $_ | Set-ADUser -UserPrincipalName $newUpn}
   ```

1. **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 **Student** 도메인 사용자에게 **adatum.com** UPN 접미사를 할당합니다.

   ```powershell
   $domainAdminUser = Get-ADUser -Filter {sAMAccountName -eq 'Student'} -Properties userPrincipalName
   $domainAdminUser | Set-ADUser -UserPrincipalName 'student@adatum.com'
   ```

#### 작업 3: 디렉터리 동기화를 구성하는 데 사용할 Azure AD 사용자 만들기

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 새 Azure AD 사용자를 만듭니다.

   ```powershell
   $userName = 'aadsyncuser'
   $passwordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
   $passwordProfile.Password = 'Pa55w.rd1234'
   $passwordProfile.ForceChangePasswordNextLogin = $false
   New-AzureADUser -AccountEnabled $true -DisplayName $userName -PasswordProfile $passwordProfile -MailNickName $userName -UserPrincipalName "$userName@$aadDomainName"
   ```

1. **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 새로 만든 Azure AD 사용자에게 전역 관리자 역할을 할당합니다. 

   ```powershell
   $aadUser = Get-AzureADUser -ObjectId "$userName@$aadDomainName"
   $aadRole = Get-AzureADDirectoryRole | Where-Object {$_.displayName -eq 'Global administrator'} 
   Add-AzureADDirectoryRoleMember -ObjectId $aadRole.ObjectId -RefObjectId $aadUser.ObjectId
   ```

   > **참고**: Azure AD PowerShell 모듈에서는 전역 관리자 역할의 명칭이 회사 관리자입니다.

1. **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 새로 만든 Azure AD 사용자의 사용자 계정 이름을 확인합니다.

   ```powershell
   (Get-AzureADUser -Filter "MailNickName eq '$userName'").UserPrincipalName
   ```

   > **참고**: 사용자 계정 이름을 적어 두세요. 이 연습 뒷부분에서 해당 이름이 필요합니다. 


#### 작업 4: Azure AD Connect 설치

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내에서 Internet Explorer를 시작하고 [비즈니스용 Microsoft Edge 다운로드 페이지](https://www.microsoft.com/en-us/edge/business/download)로 이동합니다.
1. [비즈니스용 Microsoft Edge 다운로드 페이지](https://www.microsoft.com/en-us/edge/business/download)에서 Microsoft Edge의 안정적인 최신 버전을 다운로드하여 설치 및 시작한 후 기본 설정을 사용하여 구성합니다.
1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내에서 Microsoft Edge를 사용하여 [Azure Portal](https://portal.azure.com)로 이동합니다. 메시지가 표시되면 이 랩에서 사용 중인 구독의 소유자 역할이 할당된 사용자 계정의 Azure AD 자격 증명을 사용하여 로그인합니다.
1. Azure Portal에서 Azure Portal 페이지 상단의 **리소스, 서비스 및 문서 검색** 텍스트 상자를 사용하여 **Azure Active Directory** 블레이드를 검색한 후 해당 블레이드로 이동합니다. 그런 다음 Azure AD 테넌트 블레이드 허브 메뉴의 **관리** 섹션에서 **Azure AD Connect**를 선택합니다.
1. **Azure AD Connect** 블레이드에서 **Azure AD Connect 다운로드** 링크를 선택합니다. 그러면 새 브라우저 탭이 자동으로 열리고 **Microsoft Azure Active Directory Connect** 다운로드 페이지가 표시됩니다.
1. **Microsoft Azure Active Directory Connect** 다운로드 페이지에서 **다운로드**를 선택합니다.
1. **AzureADConnect.msi** 설치 관리자 실행 또는 저장을 선택하라는 메시지가 표시되면 **실행**을 선택하여 **Microsoft Azure Active Directory Connect** 마법사를 시작합니다.
1. **Microsoft Azure Active Directory Connect** 마법사의 **Azure AD Connect 시작** 페이지에서 **라이선스 약관 및 개인 정보 보호 공지에 동의합니다**라는 체크박스를 선택하고 **계속**을 선택합니다.
1. **Microsoft Azure Active Directory Connect** 마법사의 **기본 설정** 페이지에서 **사용자 지정** 옵션을 선택합니다.
1. **필수 구성 요소 설치** 페이지에서 모든 선택적 구성 옵션의 선택을 취소하고 **설치**를 선택합니다.
1. **사용자 로그인** 페이지에서 **암호 해시 동기화**만 사용하도록 설정되었는지 확인하고 **다음**을 선택합니다.
1. **AD Azure에 연결** 페이지에서 이전 연습에서 만든 **aadsyncuser** 사용자 계정의 자격 증명을 사용하여 인증하고 **다음**을 선택합니다. 

   > **참고**: 이 연습 앞부분에서 적어 둔 **aadsyncuser** 계정의 userPrincipalName 특성을 입력하고 암호로 **Pa55w.rd1234**를 지정합니다.

1. **디렉터리 연결** 페이지에서 **adatum.com** 포리스트 항목 오른쪽에 있는 **디렉터리 추가** 단추를 선택합니다.
1. **AD 포리스트 계정** 창에서 **새 AD 계정 만들기** 옵션이 선택되었는지 확인하고 다음 자격 증명을 지정한 후 **확인**을 선택합니다:

   |설정|값|
   |---|---|
   |사용자 이름|**ADATUM\Student**|
   |암호|**Pa55w.rd1234**|

1. **디렉터리 연결** 페이지에서 **adatum.com** 항목이 구성된 디렉터리로 표시되는지 확인하고 **다음**을 선택합니다
1. **Azure AD 로그인 구성** 페이지에서 **UPN 접미사가 확인된 도메인 이름과 일치하지 않으면 사용자가 해당 온-프레미스 자격 증명을 사용하여 Azure AD에 로그인할 수 없습니다**라는 경고를 확인하고, **모든 UPN 접미사를 확인된 도메인과 일치시키지 않고 계속합니다** 체크박스에 체크한 후 **다음**을 선택합니다.

   > **참고**: Azure AD 테넌트에 **adatum.com** AD DS의 UPN 접미사 중 하나와 일치하는 확인된 사용자 지정 DNS 도메인이 없으므로, 이 경고가 표시되는 것은 정상적인 현상입니다.

1. **도메인 및 OU 필터링** 페이지에서 **선택한 도메인 및 OU 동기화** 옵션을 선택하고 adatum.com 노드를 확장합니다. 그런 다음 모든 체크박스를 선택 취소하고 **ToSync** OU 옆에 있는 체크박스만 선택한 후 **다음**을 선택합니다.
1. **사용자를 고유하게 식별** 페이지에서 기본 설정을 수락하고 **다음**을 선택합니다.
1. **사용자 및 디바이스 필터링** 페이지에서 기본 설정을 수락하고 **다음**을 선택합니다.
1. **옵션 기능** 페이지에서 기본 설정을 수락하고 **다음**을 선택합니다.
1. **구성 준비 완료** 페이지에서 **구성이 완료되면 동기화 프로세스 시작** 체크박스가 선택되었는지 확인하고 **설치**를 선택합니다.

   > **참고**: 설치에는 약 2분이 소요됩니다.

1. **구성 완료** 페이지의 정보를 검토하고 **끝내기**를 선택하여 **Microsoft Azure Active Directory Connect** 창을 닫습니다.
1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 Azure Portal가 표시된 Microsoft Edge 창에서 Adatum Lab Azure AD 테넌트의 **사용자 - 모든 사용자** 블레이드로 이동합니다.
1. **사용자 \| 모든 사용자** 블레이드에서 사용자 개체 목록에 이 랩 앞부분에서 만든 AD DS 사용자 계정 목록이 포함되어 있으며, **디렉터리가 동기화됨** 열에 **예** 항목이 표시되어 있음을 확인합니다.

   > **참고**: 몇 분 기다렸다가 브라우저 페이지를 새로 고쳐야 AD DS 사용자 계정이 표시될 수도 있습니다.