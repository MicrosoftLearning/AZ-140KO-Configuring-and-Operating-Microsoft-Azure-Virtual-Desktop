---
lab:
    title: '랩: Azure Virtual Desktop(Azure AD DS) 배포 준비'
    module: '모듈 1: AVD 아키텍처 계획'
---

# 랩 - Azure Virtual Desktop(Azure AD DS) 배포 준비
# 학생 랩 매뉴얼

## 랩 종속성

- Azure 구독
- Azure 구독과 연결된 Azure AD 테넌트의 전역 관리자 역할, 그리고 Azure 구독의 Owner 또는 Contributor 역할이 할당되어 있는 Microsoft 계정 또는 Azure AD 계정

## 예상 시간

150분

>**참고**: Azure AD DS 프로비전 시의 대기 시간은 약 90분입니다.

## 랩 시나리오

Azure AD DS(Azure Active Directory Domain Services) 환경에서 Azure Virtual Desktop 배포를 준비해야 합니다.

## 목표
  
이 랩을 완료하면 다음을 수행할 수 있습니다.

- Azure AD DS 도메인 구현
- Azure AD DS 도메인 환경 구성

## 랩 파일

-  \\\\AZ-140\\AllFiles\\Labs\\01\\az140-11_azuredeploycl11a.json
-  \\\\AZ-140\\AllFiles\\Labs\\01\\az140-11_azuredeploycl11a.parameters.json

## 지침

### 연습 0: vCPU 할당량 늘리기

이 연습의 주요 작업은 다음과 같습니다.

1. 현재 vCPU 사용량 파악
1. vCPU 할당량 늘리기 요청

#### 작업 1: 현재 vCPU 사용량 파악

1. 랩 컴퓨터에서 웹 브라우저를 시작하여 [Azure Portal](https://portal.azure.com)로 이동하고 이 랩에서 사용할 구독에서 Owner 역할을 가진 사용자 계정의 자격 증명을 제공하여 로그인합니다.
1. Azure Portal에서 검색 텍스트 상자 바로 오른쪽의 도구 모음 아이콘을 선택하여 **Cloud Shell** 창을 엽니다.
1. **Bash** 또는 **PowerShell**을 선택하라는 메시지가 표시되면 **PowerShell**을 선택합니다. 

   >**참고**: **Cloud Shell**을 처음 시작할 때 **탑재된 스토리지가 없음** 메시지가 표시되면 이 랩에서 사용하는 구독을 선택하고 **스토리지 만들기**를 선택합니다. 

1. Azure Portal의 **Cloud Shell** PowerShell 세션에서 다음을 실행하여 **Microsoft.Compute** 리소스 공급자를 등록합니다(등록되지 않은 경우).

   ```powershell
   Register-AzResourceProvider -ProviderNamespace 'Microsoft.Compute'
   ```

1. Azure Portal의 **Cloud Shell** PowerShell 세션에서 다음을 실행하여 **Microsoft.Compute** 리소스 공급자의 등록 상태를 확인합니다.

   ```powershell
   Get-AzResourceProvider -ListAvailable | Where-Object {$_.ProviderNamespace -eq 'Microsoft.Compute'}
   ```

   >**참고**: 상태가 **등록됨**로 나와 있는지 확인합니다. 그렇지 않은 경우 몇 분 기다렸다가 이 단계를 반복합니다.

1. Azure Portal의 **Cloud Shell** PowerShell 세션에서 다음 명령을 실행하여 현재 vCPU 사용량, 그리고 **StandardDSv3Family** 및 **StandardBSFamily** Azure VM의 vCPU 사용량 한도를 확인합니다(`<Azure_region>` 자리 표시자는 `eastus` 등 이 랩에서 사용하려는 Azure 지역의 이름으로 바꿔야 함).

   ```powershell
   $location = '<Azure_region>'
   Get-AzVMUsage -Location $location | Where-Object {$_.Name.Value -eq 'StandardDSv3Family'}
   Get-AzVMUsage -Location $location | Where-Object {$_.Name.Value -eq 'StandardBSFamily'}
   ```

   > **참고**: Azure 지역의 이름을 확인하려면 **Cloud Shell**의 PowerShell 프롬프트에서 `(Get-AzLocation).Location`을 실행합니다.
   
1. 이전 단계에서 실행한 명령 출력을 검토하여 대상 Azure 지역에서 Azure VM의 **Standard DSv3 Family** 및 **StandardBSFamily** 둘 다에서 사용 가능한 vCPU가 **20**개 이상인지 확인합니다. 사용 가능한 vCPU가 20개 이상인 경우에는 다음 연습부터 바로 진행하면 됩니다. 그렇지 않은 경우에는 이 연습의 다음 작업을 계속 진행합니다. 

#### 작업 2: vCPU 할당량 늘리기 요청

1. Azure Portal에서 **구독**을 검색하여 선택하고 **구독** 블레이드에서 이 랩에 사용할 Azure 구독에 해당하는 항목을 선택합니다.
1. Azure Portal의 구독 블레이드 왼쪽 세로 메뉴에 있는 **설정** 섹션에서 **사용량 및 할당량**을 선택합니다. 
1. 구독의 **사용량 및 할당량** 블레이드에서 **증가 요청**을 선택합니다.
1. **새 지원 요청** 블레이드의 **기본** 탭에서 다음 항목을 지정하고 **다음: 솔루션 >** 을 선택합니다.

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

   >**참고**: 여기서는 랩 환경 실행 비용을 최소화하기 위해 **BS Series** Azure VM을 사용합니다. Azure Virtual Desktop 시나리오에서 반드시 **BS Series** Azure VM을 사용해야 하는 것은 아닙니다.

1. **새 지원 요청** 블레이드의 **세부 정보** 탭으로 돌아와 다음 항목을 지정하고 **다음: 검토 + 만들기 >** 를 선택합니다.

   |설정|값|
   |---|---|
   |심각도|**C - 최소 영향**|
   |기본 연락 방법|원하는 옵션을 선택하고 연락처 세부 정보 입력|
    
1. **새 지원 요청** 블레이드의 **검토 + 만들기** 탭에서 **만들기**를 선택합니다.

   > **참고**: 이 vCPU 범위 내의 할당량 늘리기 요청은 대개 몇 시간 내에 완료됩니다. 하지만 이를 기다리지 않고 이 랩을 완료해도 됩니다.


### 연습 1: Azure Active Directory Domain Services(AD DS) 도메인 구현

이 연습의 주요 작업은 다음과 같습니다.

1. Azure AD DS 도메인 관리용 Azure AD 사용자 계정 만들기 및 구성
1. Azure Portal을 사용하여 Azure AD DS 인스턴스 배포
1. Azure AD DS 배포의 네트워크 및 ID 설정 구성

#### 작업 1: Azure AD DS 도메인 관리용 Azure AD 사용자 계정 만들기 및 구성

1. 랩 컴퓨터에서 웹 브라우저를 시작하고 [Azure Portal](https://portal.azure.com)로 이동합니다. 그런 다음 이 랩에서 사용할 구독의 Owner 역할, 그리고 Azure 구독과 연결된 Azure AD 테넌트의 전역 관리자 역할이 할당된 사용자 계정의 자격 증명을 입력하여 로그인합니다.
1. Azure Portal이 표시된 웹 브라우저에서 Azure AD 테넌트의 **개요** 블레이드로 이동한 후 왼쪽 세로 메뉴에 있는 **관리** 섹션에서 **속성**을 클릭합니다.
1. Azure AD 테넌트 **속성** 블레이드의 블레이드 맨 아래쪽에서 **보안 관리 기본값** 링크를 선택합니다.
1. **보안 기본값 사용** 블레이드에서 필요한 경우 **아니요**를 선택하고 **내 조직에서 조건부 액세스를 사용 중임** 체크박스를 선택한 후 **저장**을 선택합니다.
1. Azure Portal에서 검색 텍스트 상자의 오른쪽에 있는 도구 모음 아이콘을 직접 선택하여 **Cloud Shell** 창을 엽니다.
1. **Bash** 또는 **PowerShell**을 선택하라는 메시지가 표시되면 **PowerShell**을 선택합니다. 

   >**참고**: **Cloud Shell**을 처음 시작할 때 **탑재된 스토리지가 없음** 메시지가 표시되면 이 랩에서 사용하는 구독을 선택하고 **스토리지 만들기**를 선택합니다. 

1. Cloud Shell 창에서 다음 명령을 실행하여 Azure AD 테넌트에 로그인합니다.

   ```powershell
   Connect-AzureAD
   ```

1. Cloud Shell 창에서 다음 명령을 실행하여 Azure 구독과 연결된 Azure AD 테넌트의 기본 DNS 도메인 이름을 검색합니다.

   ```powershell
   $aadDomainName = ((Get-AzureAdTenantDetail).VerifiedDomains)[0].Name
   ```

1. Cloud Shell 창에서 다음을 실행하여 상승된 권한을 부여받을 Azure AD 사용자를 만듭니다(`<password>` 자리 표시자는 복잡한 임의 암호로 바꿈).

   > **참고**: 사용한 암호는 잘 기억해 두세요. 이 랩의 뒷부분과 이어지는 랩에서 해당 암호를 사용해야 합니다.

   ```powershell
   $passwordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
   $passwordProfile.Password = '<password>'
   $passwordProfile.ForceChangePasswordNextLogin = $false
   New-AzureADUser -AccountEnabled $true -DisplayName 'aadadmin1' -PasswordProfile $passwordProfile -MailNickName 'aadadmin1' -UserPrincipalName "aadadmin1@$aadDomainName"
   New-AzureADUser -AccountEnabled $true -DisplayName 'wvdaadmin1' -PasswordProfile $passwordProfile -MailNickName 'wvdaadmin1' -UserPrincipalName "wvdaadmin1@$aadDomainName"
   ```

1. Cloud Shell 창에서 다음 명령을 실행하여 새로 만든 첫 번째 Azure AD 사용자에게 전역 관리자 역할을 할당합니다.

   ```powershell
   $aadUser = Get-AzureADUser -ObjectId "aadadmin1@$aadDomainName"
   $aadRole = Get-AzureADDirectoryRole | Where-Object {$_.displayName -eq 'Global administrator'}
   Add-AzureADDirectoryRoleMember -ObjectId $aadRole.ObjectId -RefObjectId $aadUser.ObjectId
   ```

   > **참고**: Azure AD PowerShell 모듈에서는 전역 관리자 역할의 명칭이 회사 관리자입니다.

1. Cloud Shell 창에서 다음 명령을 실행하여 새로 만든 Azure AD 사용자의 사용자 계정 이름을 확인합니다.

   ```powershell
   (Get-AzureADUser -Filter "MailNickName eq 'aadadmin1'").UserPrincipalName
   ```

   > **참고**: 사용자 계정 이름을 적어 두세요. 이 연습 뒷부분에서 해당 이름이 필요합니다. 

1. Cloud Shell 창을 닫습니다.
1. Azure Portal 내에서 **구독**을 검색하여 선택하고 **구독** 블레이드에서 이 랩에 사용 중인 Azure 구독을 선택합니다. 
1. Azure 구독 속성이 표시된 블레이드에서 **액세스 제어(IAM)**, **+ 추가**를 차례로 선택하고 드롭다운 목록에서 **역할 할당 추가**를 선택합니다. 
1. **역할 할당 추가** 블레이드에서 다음 설정을 지정하고 **저장**을 선택합니다.

   |설정|값|
   |---|---|
   |역할|**소유자**|
   |액세스 권한 할당 대상|**사용자, 그룹 또는 서비스 주체**|
   |선택|**aadadmin1**|

   > **참고**: 이 랩의 뒷부분에서 **aadadmin1** 계정을 사용하여 Azure AD DS에 조인된 Windows 10 Azure VM에서 Azure 구독 및 해당 구독의 Azure AD 테넌트를 관리합니다. 


#### 작업 2: Azure Portal을 사용하여 Azure AD DS 인스턴스 배포

1. 랩 컴퓨터에 표시된 Azure Portal에서 **Azure AD Domain Services**를 검색하여 선택하고 **Azure AD Domain Services** 블레이드에서 **+ 추가**를 선택합니다. 그러면 **Azure AD Domain Services 만들기** 블레이드가 열립니다.
1. **Azure AD Domain Services 만들기** 블레이드의 **기본** 탭에서 다음 설정을 지정하고 **다음**을 선택합니다(나머지는 기존 값을 그대로 유지).

   |설정|값|
   |---|---|
   |구독|이 랩에서 사용 중인 Azure 구독의 이름|
   |리소스 그룹|새 리소스 그룹 **az140-11a-RG**의 이름|
   |DNS 도메인 이름|**adatum.com**|
   |지역|AVD 배포를 호스트할 지역의 이름|
   |SKU|**Standard**|
   |포리스트 유형|**사용자**|

   > **참고**: 기술적 측면에서는 도메인 이름이 반드시 고유할 필요는 없지만, 일반적으로는 기존 Azure 또는 온-프레미스 DNS 네임스페이스와 다른 Azure AD DS 도메인 이름을 할당해야 합니다.

1. **Azure AD Domain Services 만들기** 블레이드의 **네트워킹** 탭에서 **가상 네트워크** 드롭다운 목록 옆의 **새로 만들기**를 선택합니다.
1. **가상 네트워크 만들기** 블레이드에서 다음 설정을 할당하고 **확인**을 선택합니다.

   |설정|값|
   |---|---|
   |이름|**az140-aadds-vnet11a**|
   |주소 범위|**10.10.0.0/16**|
   |서브넷 이름|**aadds-Subnet**|
   |서브넷 이름|**10.10.0.0/24**|

1. **가상 네트워크 만들기** 블레이드의 **네트워킹** 탭으로 돌아와 **다음**을 선택합니다(나머지는 기존 값을 그대로 유지).
1. **Azure AD Domain Services 만들기** 블레이드의 **관리** 탭에서 기본 설정을 적용하고 **다음**을 선택합니다.
1. **Azure AD Domain Services 만들기** 블레이드의 **동기화** 탭에서 **모두**가 선택되어 있는지 확인하고 **다음**을 선택합니다.
1. **Azure AD Domain Services 만들기** 블레이드의 **보안 설정** 탭에서 기본 설정을 적용하고 **다음**을 선택합니다.
1. **Azure AD Domain Services 만들기** 블레이드의 **검토 + 만들기** 탭에서 **만들기**를 선택합니다. 
1. Azure AD DS 도메인을 만든 후에는 변경할 수 없는 설정 관련 알림을 검토하고 **확인**을 선택합니다.

   >**참고**: Azure AD DS 도메인을 프로비전한 후에는 변경할 수 없는 설정으로는 도메인의 DNS 이름, Azure 구독, 리소스 그룹, 도메인 컨트롤러를 호스트하는 가상 네트워크와 서브넷, 포리스트 유형 등이 있습니다.

   > **참고**: 배포가 완료될 때까지 기다린 후 다음 연습을 진행합니다. 배포가 완료되려면 90분 정도 걸립니다. 

#### 작업 3: Azure AD DS 배포의 네트워크 및 ID 설정 구성

1. 랩 컴퓨터에 표시된 Azure Portal에서 **Azure AD Domain Services**를 검색하여 선택하고 **Azure AD Domain Services** 블레이드에서 **adatum.com** 항목을 선택하여 새로 프로비전한 Azure AD DS 인스턴스로 이동합니다. 
1. Azure AD DS 인스턴스의 **adatum.com** 블레이드에서 **관리되는 도메인에서 구성 문제가 감지되었음**으로 시작하는 경고를 클릭합니다. 
1. **adatum.com | 구성 진단(미리 보기)** 블레이드에서 **실행**을 클릭합니다.
1. **유효성 검사** 섹션에서 **DNS 레코드** 창을 확장하고 **수정**을 클릭합니다.
1. **DNS 레코드** 블레이드에서 **수정**을 다시 클릭합니다.
1. Azure AD DS 인스턴스의 **adatum.com** 블레이드로 다시 이동하여 **필수 구성 단계** 섹션에서 Azure AD DS 암호 해시 동기화 관련 정보를 검토합니다. 

   > **참고**: Azure AD DS 도메인 컴퓨터 및 해당 리소스에 액세스할 수 있어야 하는 모든 기존 클라우드 전용 사용자는 암호를 변경하거나 초기화해야 합니다. 이 랩의 앞부분에서 만든 **aadadmin1** 계정도 마찬가지입니다.

1. 랩 컴퓨터에 표시된 Azure Portal의 **Cloud Shell** 창에서 **PowerShell**세션을 엽니다.
1. Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 Azure AD **aadadmin1** 사용자 계정의 objectID 특성을 확인합니다.

   ```powershell
   Connect-AzureAD
   $objectId = (Get-AzureADUser -Filter "MailNickName eq 'aadadmin1'").ObjectId
   ```

1. Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 이전 단계에서 objectID를 확인한 **aadadmin1** 사용자 계정의 암호를 초기화합니다(`<password>` 자리 표시자는 복잡한 임의 암호로 바꿈).

   > **참고**: 사용한 암호는 잘 기억해 두세요. 이 랩의 뒷부분과 이어지는 랩에서 해당 암호를 사용해야 합니다.

   ```powershell
   $password = ConvertTo-SecureString '<password>' -AsPlainText -Force
   Set-AzureADUserPassword -ObjectId $objectId -Password $password -ForceChangePasswordNextLogin $false
   ```

   > **참고**: 실제 시나리오에서는 대개 **-ForceChangePasswordNextLogin**의 값을 $true로 설정합니다. 여기서는 랩 단계를 간편하게 실행하기 위해 값으로 **$false**를 선택했습니다. 

1. 이전 두 단계를 반복하여 **wvdaadmin1** 사용자 계정의 암호를 재설정합니다.


### 연습 2: Azure AD DS 도메인 환경 구성
  
이 연습의 주요 작업은 다음과 같습니다.

1. Azure Resource Manager 빠른 시작 템플릿을 사용하여 Windows 10을 실행하는 Azure VM 배포
1. Azure Bastion 배포
1. Azure AD DS 도메인의 기본 구성 검토
1. Azure AD DS에 동기화할 AD DS 사용자 및 그룹 만들기

#### 작업 1: Azure Resource Manager 빠른 시작 템플릿을 사용하여 Windows 10을 실행하는 Azure VM 배포

1. 랩 컴퓨터에 표시된 Azure Portal 내 Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 이전 작업에서 만든 **az140-aadds-vnet11a** 가상 네트워크에 서브넷 **cl-Subnet**을 추가합니다.

   ```powershell
   $resourceGroupName = 'az140-11a-RG'
   $vnet = Get-AzVirtualNetwork -ResourceGroupName $resourceGroupName -Name 'az140-aadds-vnet11a'
   $subnetConfig = Add-AzVirtualNetworkSubnetConfig `
     -Name 'cl-Subnet' `
     -AddressPrefix 10.10.255.0/24 `
     -VirtualNetwork $vnet
   $vnet | Set-AzVirtualNetwork
   ```

1. Azure Portal의 Cloud Shell 창 도구 모음에서 **파일 업로드/다운로드** 아이콘을 선택하고 드롭다운 메뉴에서 **업로드**를 선택합니다. 그런 다음 **\\\\AZ-140\\AllFiles\\Labs\\01\\az140-11_azuredeploycl11a.json** 및 **\\\\AZ-140\\AllFiles\\Labs\\01\\az140-11_azuredeploycl11a.parameters.json** 파일을 Cloud Shell 홈 디렉터리에 업로드합니다.
1. Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 Windows 10을 실행하는 Azure VM을 배포합니다. 이 VM은 Azure Virtual Desktop 클라이언트로 사용되며, Azure AD DS 도메인에 Azure Virtual Desktop 클라이언트를 연결합니다.

   ```powershell
   $resourceGroupName = 'az140-11a-RG'
   $location = (Get-AzResourceGroup -ResourceGroupName $resourceGroupName).Location
   New-AzResourceGroupDeployment `
     -ResourceGroupName $resourceGroupName `
     -Location $location `
     -Name az140lab0101vmDeployment `
     -TemplateFile $HOME/az140-11_azuredeploycl11a.json `
     -TemplateParameterFile $HOME/az140-11_azuredeploycl11a.parameters.json
   ```

   > **참고**: 배포는 10분 정도 걸릴 수 있습니다. 다음 작업을 진행하기 전에 배포가 완료될 때까지 기다립니다. 


#### 작업 2: Azure Bastion 배포 

> **참고**: Azure Bastion을 사용하면 이 연습의 이전 작업에서 배포한 공용 엔드포인트 없이 Azure VM에 연결할 수 있으며, 운영 체제 수준 자격 증명을 노리는 무차별 암호 대입 익스플로잇으로부터 보호를 받습니다.

> **참고**: 브라우저에서 팝업 기능이 사용되고 있는지 확인하세요.

1. Azure Portal을 표시하는 브라우저 창에서 다른 탭을 열고, 브라우저 탭에서 Azure Portal로 이동합니다.
1. Azure Portal에서 검색 텍스트 상자의 오른쪽에 있는 도구 모음 아이콘을 직접 선택하여 **Cloud Shell** 창을 엽니다.
1. Cloud Shell 창의 PowerShell 세션에서 다음을 실행하여 이전 연습에서 만든 **az140-aadds-vnet11** 가상 네트워크에 서브넷 **AzureBastionSubnet**을 추가합니다.

   ```powershell
   $resourceGroupName = 'az140-11a-RG'
   $vnet = Get-AzVirtualNetwork -ResourceGroupName $resourceGroupName -Name 'az140-aadds-vnet11a'
   $subnetConfig = Add-AzVirtualNetworkSubnetConfig `
     -Name 'AzureBastionSubnet' `
     -AddressPrefix 10.10.254.0/24 `
     -VirtualNetwork $vnet
   $vnet | Set-AzVirtualNetwork
   ```

1. Cloud Shell 창을 닫습니다.
1. Azure Portal에서 **Bastion**을 검색하여 선택하고 **Bastion** 블레이드에서 **+ 만들기**를 선택합니다.
1. **Bastion 만들기** 블레이드의 **기본** 탭에서 다음 설정을 지정하고 **검토 + 만들기**를 선택합니다.

   |설정|값|
   |---|---|
   |구독|이 랩에서 사용 중인 Azure 구독의 이름|
   |리소스 그룹|**az140-11a-RG**|
   |이름|**az140-11a-bastion**|
   |지역|이 연습의 이전 작업에서 리소스를 배포한 것과 동일한 Azure 지역|
   |계층|**기본**|
   |가상 네트워크|**az140-aadds-vnet11a**|
   |서브넷|**AzureBastionSubnet (10.10.254.0/24)**|
   |공용 IP 주소|**새로 만들기**|
   |공용 IP 이름|**az140-aadds-vnet11a-ip**|

1. **Bastion 만들기** 블레이드의 **검토 + 만들기** 탭에서 **만들기**를 선택합니다.

   > **참고**: 이 연습의 다음 작업을 진행하기 전에 배포가 완료될 때까지 기다립니다. 배포는 5분 정도 걸릴 수 있습니다.


#### 작업 3: Azure AD DS 도메인의 기본 구성 검토

> **참고**: Azure AD DS에 새로 조인된 컴퓨터에 로그인하려면 로그인하려는 사용자 계정을 **AAD DC Administrators** Azure AD 그룹에 추가해야 합니다. 이 Azure AD 그룹은 Azure AD DS 인스턴스를 프로비전한 Azure 구독과 연결되어 있는 Azure AD 테넌트에 자동 작성됩니다.

> **참고**: Azure AD DS 인스턴스를 프로비전할 때 이 그룹에 기존 Azure AD 사용자 계정을 추가할 수 있습니다.

1. 랩 컴퓨터에 표시된 Azure Portal 내 Cloud Shell 창에서 다음 명령을 실행하여 Azure AD 그룹 **AAD DC Administrators**에 Azure AD 사용자 계정 **aadadmin1**을 추가합니다.

   ```powershell
   Connect-AzureAD
   $groupObjectId = (Get-AzureADGroup -Filter "DisplayName eq 'AAD DC Administrators'").ObjectId
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aadadmin1'").ObjectId
   Add-AzureADGroupMember -ObjectId $groupObjectId -RefObjectId $userObjectId
   ```

1  Cloud Shell 창을 닫습니다.
1. 랩 컴퓨터에 표시된 Azure Portal에서 **가상 머신**을 검색하여 선택하고 **가상 머신** 블레이드에서 **az140-cl-vm11a** 항목을 선택합니다. 그러면 **az140-cl-vm11a** 블레이드가 열립니다.
1. **az140-cl-vm11a** 블레이드에서 **연결**을 선택하고 드롭다운 메뉴에서 **Bastion**을 선택합니다. 그런 다음 **az140-cl-vm11a \| 연결** 블레이드의 **Bastion** 탭에서 **Bastion 사용**을 선택합니다.
1. 메시지가 표시되면 **aadadmin1** 사용자로 로그인합니다. 이 랩 앞부분에서 확인한 해당 사용자의 계정 이름, 그리고 랩 앞부분에서 사용자 계정을 만들 때 설정한 암호를 사용하면 됩니다.
1. **az140-cl-vm11a** Azure VM에 연결된 원격 데스크톱 세션 내에서 **Windows PowerShell ISE**를 관리자 권한으로 시작합니다. 그런 다음 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 Active Directory 및 DNS 관련 원격 서버 관리 도구를 설치합니다.

   ```powershell
   Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online
   Add-WindowsCapability -Name Rsat.Dns.Tools~~~~0.0.1.0 -Online
   Add-WindowsCapability -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0 -Online
   Add-WindowsCapability -Name Rsat.ServerManager.Tools~~~~0.0.1.0 -Online
   ```

   > **참고**: 설치가 완료될 때까지 기다렸다가 다음 단계를 진행합니다. 완료되려면 2분 정도 걸립니다.

1. **az140-cl-vm11a** Azure VM에 연결된 원격 데스크톱 내의 **시작** 메뉴에서 **Windows 관리 도구** 폴더로 이동하여 해당 폴더를 확장하고 도구 목록에서 **Active Directory 사용자 및 컴퓨터**를 선택합니다. 
1. **Active Directory 사용자 및 컴퓨터** 콘솔에서 **AADDC Computers** 및 **AADDC Users** 조직 구성 단위를 포함한 기본 계층 구조를 검토합니다. AADDC Computers 조직 구성 단위에는 **az140-cl-vm11a** 컴퓨터 계정이 포함되어 있습니다. 그리고 AADDC Users 조직 구성 단위에는 Azure AD DS 인스턴스 배포를 호스트하는 Azure 구독과 연결된 Azure AD 테넌트에서 동기화되는 사용자 계정이 포함되어 있습니다. **AADDC Users** 조직 구성 단위에는 동일 Azure AD 테넌트에서 동기화되는 **AAD DC Administrators** 그룹도 포함되어 있습니다. 이 멤버 자격은 Azure AD DS 도메인 내에서 직접 수정할 수는 없으며 Azure AD DS 테넌트 내에서 관리해야 합니다. 변경 내용은 Azure AD DS 도메인에서 호스트되는 그룹 복제본과 자동 동기화됩니다. 

   > **참고**: 현재 이 그룹에는 **aadadmin1** 사용자 계정만 포함되어 있습니다.

1. **Active Directory 사용자 및 컴퓨터** 콘솔의 **AADDC Users** OU에서 **aadadmin1** 사용자 계정을 선택하여 해당 **속성** 대화 상자를 표시합니다. 그런 다음 **계정** 탭으로 전환하여 사용자 계정 이름 접미사가 기본 Azure AD DNS 도메인 이름과 일치하며 수정 불가능한 상태임을 확인합니다. 
1. **Active Directory 사용자 및 컴퓨터** 콘솔에서 **Domain Controllers** 조직 구성 단위의 내용을 검토하여 임의로 생성된 이름이 지정되어 있는 도메인 컨트롤러 2개의 컴퓨터 계정이 포함되어 있음을 확인합니다. 

#### 작업 4: Azure AD DS에 동기화할 AD DS 사용자 및 그룹 만들기

1. **az140-cl-vm11a** Azure VM에 연결된 원격 데스크톱 세션 내에서 Microsoft Edge를 시작하고 [Azure Portal](https://portal.azure.com)로 이동합니다. 그런 다음 사용자 계정 이름으로 **aadadmin1** 사용자 계정을, 암호로는 이 랩 앞부분에서 설정한 암호를 입력하여 로그인합니다.
1. Azure Portal에서 **Cloud Shell**을 엽니다.
1. **Bash** 또는 **PowerShell**을 선택하라는 메시지가 표시되면 **PowerShell**을 선택합니다. 

   >**참고**: **aadadmin1** 사용자 계정을 사용하여 **Cloud Shell**을 처음 시작하는 경우 Cloud Shell 홈 디렉터리를 구성해야 합니다. **탑재된 스토리지가 없음** 메시지가 표시되면 이 랩에서 사용하는 구독을 선택하고 **스토리지 만들기**를 선택합니다. 

1. Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 Azure AD 테넌트에 로그인한 후 인증합니다.

   ```powershell
   Connect-AzureAD
   ```

1. Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 Azure 구독과 연결된 Azure AD 테넌트의 기본 DNS 도메인 이름을 검색합니다.

   ```powershell
   $aadDomainName = ((Get-AzureAdTenantDetail).VerifiedDomains)[0].Name
   ```

1. Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 이후 랩에서 사용할 Azure AD 사용자 계정을 만듭니다(`<password>` 자리 표시자는 복잡한 임의 암호로 바꿈).

   > **참고**: 사용한 암호는 잘 기억해 두세요. 이 랩의 뒷부분과 이어지는 랩에서 해당 암호를 사용해야 합니다.

   ```powershell
   $passwordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
   $passwordProfile.Password = '<password>'
   $passwordProfile.ForceChangePasswordNextLogin = $false
   $aadUserNamePrefix = 'aaduser'
   $userCount = 1..9
   foreach ($counter in $userCount) {
     New-AzureADUser -AccountEnabled $true -DisplayName "$aadUserNamePrefix$counter" -PasswordProfile $passwordProfile -MailNickName "$aadUserNamePrefix$counter" -UserPrincipalName "$aadUserNamePrefix$counter@$aadDomainName"
   } 
   ```

1. Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 Azure AD 그룹 **az140-wvd-aadmins**를 만든 후 **aadadmin1** 및 **wvdaadmin1** 사용자 계정에 추가합니다.

   ```powershell
   $az140wvdaadmins = New-AzureADGroup -Description 'az140-wvd-aadmins' -DisplayName 'az140-wvd-aadmins' -MailEnabled $false -SecurityEnabled $true -MailNickName 'az140-wvd-aadmins'
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aadadmin1'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdaadmins.ObjectId -RefObjectId $userObjectId
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'wvdaadmin1'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdaadmins.ObjectId -RefObjectId $userObjectId
   ```

1. Cloud Shell 창에서 이전 단계를 반복하여 이후 랩에서 사용할 사용자용 Azure AD 그룹을 만든 후 앞에서 만든 Azure AD 사용자 계정에 추가합니다.

   ```powershell
   $az140wvdausers = New-AzureADGroup -Description 'az140-wvd-ausers' -DisplayName 'az140-wvd-ausers' -MailEnabled $false -SecurityEnabled $true -MailNickName 'az140-wvd-ausers'
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aaduser1'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdausers.ObjectId -RefObjectId $userObjectId
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aaduser2'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdausers.ObjectId -RefObjectId $userObjectId
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aaduser3'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdausers.ObjectId -RefObjectId $userObjectId
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aaduser4'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdausers.ObjectId -RefObjectId $userObjectId
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aaduser5'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdausers.ObjectId -RefObjectId $userObjectId
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aaduser6'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdausers.ObjectId -RefObjectId $userObjectId
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aaduser7'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdausers.ObjectId -RefObjectId $userObjectId
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aaduser8'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdausers.ObjectId -RefObjectId $userObjectId
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aaduser9'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdausers.ObjectId -RefObjectId $userObjectId

   $az140wvdaremoteapp = New-AzureADGroup -Description "az140-wvd-aremote-app" -DisplayName "az140-wvd-aremote-app" -MailEnabled $false -SecurityEnabled $true -MailNickName "az140-wvd-aremote-app"
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aaduser1'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdaremoteapp.ObjectId -RefObjectId $userObjectId
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aaduser5'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdaremoteapp.ObjectId -RefObjectId $userObjectId
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aaduser6'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdaremoteapp.ObjectId -RefObjectId $userObjectId

   $az140wvdapooled = New-AzureADGroup -Description "az140-wvd-apooled" -DisplayName "az140-wvd-apooled" -MailEnabled $false -SecurityEnabled $true -MailNickName "az140-wvd-apooled"
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aaduser1'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdapooled.ObjectId -RefObjectId $userObjectId
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aaduser2'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdapooled.ObjectId -RefObjectId $userObjectId
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aaduser3'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdapooled.ObjectId -RefObjectId $userObjectId
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aaduser4'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdapooled.ObjectId -RefObjectId $userObjectId

   $az140wvdapersonal = New-AzureADGroup -Description "az140-wvd-apersonal" -DisplayName "az140-wvd-apersonal" -MailEnabled $false -SecurityEnabled $true -MailNickName "az140-wvd-apersonal"
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aaduser7'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdapersonal.ObjectId -RefObjectId $userObjectId
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aaduser8'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdapersonal.ObjectId -RefObjectId $userObjectId
   $userObjectId = (Get-AzureADUser -Filter "MailNickName eq 'aaduser9'").ObjectId
   Add-AzureADGroupMember -ObjectId $az140wvdapersonal.ObjectId -RefObjectId $userObjectId
   ```

1. Cloud Shell 창을 닫습니다.
1. **az140-cl-vm11a** Azure VM에 연결된 원격 데스크톱 내의 Azure Portal이 표시된 Microsoft Edge 창에서 **Azure Active Directory** 블레이드를 검색하여 선택합니다. 그런 다음 Azure AD 테넌트 블레이드 왼쪽의 세로 메뉴 모음에 있는 **관리**섹션에서 **사용자**를 선택합니다. 그런 후에 **사용자 \| 모든 사용자** 블레이드에서 새 사용자 계정이 작성되었음을 확인합니다.
1. Azure AD 테넌트 블레이드로 다시 이동하여 왼쪽 세로 메뉴 모음에 있는 **관리** 섹션에서 **그룹**을 선택합니다. 그런 후에 **그룹 \| 모든 그룹** 블레이드에서 새 그룹 계정이 작성되었음을 확인합니다.
1. **az140-cl-vm11a** Azure VM에 연결된 원격 데스크톱 내에서 **Active Directory 사용자 및 컴퓨터** 콘솔로 전환합니다. 그런 다음 **Active Directory 사용자 및 컴퓨터** 콘솔에서 **AADDC Users** OU로 이동하여 동일한 사용자 및 그룹 계정이 포함되어 있는지 확인합니다.

   >**참고**: 콘솔 보기를 새로 고쳐야 할 수도 있습니다.
