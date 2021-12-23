---
lab:
    title: '랩: 호스트 풀에서 자동 크기 조정 구현(AD DS)'
    module: '모듈: WVD 인프라 모니터링 및 유지 관리'
---

# 랩 - 호스트 풀에서 자동 크기 조정 구현(AD DS)
# 학생 랩 매뉴얼

## 랩 종속성

- 이 랩에서 사용할 Azure 구독
- 이 랩에서 사용할 Azure 구독에 대한 Owner 또는 Contributor 역할, 그리고 해당 Azure 구독에 연결된 Azure AD 테넌트의 전역 관리자 역할이 할당되어 있는 Microsoft 계정 또는 Azure AD 계정
- **Azure Virtual Desktop의 배포 준비(AD DS)** 랩 완료
- **Azure Portal을 사용하여 호스트 풀 및 세션 호스트 배포(AD DS)** 랩 완료

## 예상 소요 시간

60분

## 랩 시나리오

Active Directory Domain Services(AD DS) 환경에서 Azure Virtual Desktop 세션 호스트의 자동 크기 조정을 구성해야 합니다.

## 목표
  
이 랩을 완료하면 다음을 수행할 수 있습니다.

- Azure Virtual Desktop 세션 호스트의 자동 크기 조정 구성
- Azure Virtual Desktop 세션 호스트의 자동 크기 조정 확인

## 랩 파일

- 없음

## 지침

### 연습 1: Azure Virtual Desktop 세션 호스트의 자동 크기 조정 구성

이 연습의 주요 작업은 다음과 같습니다.

1. Azure Virtual Desktop 세션 호스트의 자동 크기 조정 준비
1. Azure Automation 계정 만들기 및 구성
1. Azure 논리 앱 만들기

#### 작업 1: Azure Virtual Desktop 세션 호스트의 자동 크기 조정 준비

1. 랩 컴퓨터에서 웹 브라우저를 시작하고 [Azure Portal](https://portal.azure.com)로 이동합니다. 그런 다음 이 랩에서 사용할 구독의 Owner 역할이 할당된 사용자 계정의 자격 증명을 입력하여 로그인합니다.
1. 랩 컴퓨터의 Azure Portal이 표시된 웹 브라우저 창에서 **Cloud Shell** 창 내에 **PowerShell** 셸 세션을 엽니다.
1. Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 이 랩에서 사용할 Azure Virtual Desktop 세션 호스트 Azure VM을 시작합니다.

   ```powershell
   Get-AzVM -ResourceGroup 'az140-21-RG' | Start-AzVM -NoWait
   ```

   >**참고**: 명령은 비동기적으로 실행되므로(-NoWait 매개 변수에 의해 결정됨) 동일한 PowerShell 세션 내에서 즉시 다른 PowerShell 명령을 실행할 수는 있지만, Azure VM이 실제로 시작되려면 몇 분 정도 걸립니다. 

#### 작업 2: Azure Automation 계정 만들기 및 구성

1. 랩 컴퓨터에서 웹 브라우저를 시작하고 [Azure Portal](https://portal.azure.com)로 이동합니다. 그런 다음 이 랩에서 사용할 구독의 Owner 역할이 할당된 사용자 계정의 자격 증명을 입력하여 로그인합니다.
1. Azure Portal에서 **가상 머신**을 검색하여 선택하고 **가상 머신** 블레이드에서 **az140-dc-vm11**을 선택합니다.
1. **az140-dc-vm11** 블레이드에서 **연결**을 선택하고 드롭다운 메뉴에서 **Bastion**을 선택합니다. 그런 다음 **az140-dc-vm11 \| 연결** 블레이드의 **Bastion** 탭에서 **Bastion 사용**을 선택합니다.
1. 메시지가 표시되면 다음 자격 증명을 제공하고 **연결**을 선택합니다.

   |설정|값|
   |---|---|
   |사용자 이름|**Student**|
   |암호|**Pa55w.rd1234**|

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내에서 **Windows PowerShell ISE**를 관리자 권한으로 시작합니다.
1. **관리자: Windows PowerShell ISE** 콘솔에서 다음 명령을 실행하여 Azure 구독에 로그인합니다.

   ```powershell
   Connect-AzAccount
   ```

1. 메시지가 표시되면 이 랩에서 사용 중인 구독의 Owner 역할이 할당된 사용자 계정의 Azure AD 자격 증명을 사용하여 로그인합니다.
1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 자동 크기 조정 솔루션의 일부분인 Azure Automation 계정을 만드는 데 사용할 PowerShell 스크립트를 다운로드합니다.

   ```powershell
   [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
   $labFilesfolder = 'C:\Allfiles\Labs\05'
   New-Item -ItemType Directory -Path $labFilesfolder -Force
   Set-Location -Path $labFilesfolder
   $uri = 'https://raw.githubusercontent.com/Azure/RDS-Templates/master/wvd-templates/wvd-scaling-script/CreateOrUpdateAzAutoAccount.ps1'
   Invoke-WebRequest -Uri $Uri -OutFile '.\CreateOrUpdateAzAutoAccount.ps1'
   ```

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 스크립트 매개 변수에 할당할 변수의 값을 설정합니다.

   ```powershell
   $aadTenantId = (Get-AzContext).Tenant.Id
   $subscriptionId = (Get-AzContext).Subscription.Id
   $resourceGroupName = 'az140-51-RG'
   $location = (Get-AzVirtualNetwork -ResourceGroupName 'az140-11-RG' -Name 'az140-adds-vnet11').Location
   $suffix = Get-Random
   $automationAccountName = "az140-automation-51$suffix"
   $workspaceName = "az140-workspace-51$suffix"
   ```

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 이 랩에서 사용할 리소스 그룹을 만듭니다.

   ```powershell
   New-AzResourceGroup -ResourceGroupName $resourceGroupName -Location $location
   ```

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 이 랩에서 사용할 Azure Log Analytics 작업 영역을 만듭니다.

   ```powershell
   New-AzOperationalInsightsWorkspace -Location $location -Name $workspaceName -ResourceGroupName $resourceGroupName
   ```

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE**에서 **C:\\Allfiles\\Labs\\05\\CreateOrUpdateAzAutoAccount.ps1** 스크립트를 열고 줄 **82**와 **86** 사이의 코드를 다음과 같이 여러 줄 주석으로 설정합니다.

   ```powershell
   <#
   # 인증된 사용자의 역할 할당 가져오기
   $RoleAssignments = Get-AzRoleAssignment -SignInName $AzContext.Account -ExpandPrincipalGroups
   if (!($RoleAssignments | Where-Object { $_.RoleDefinitionName -in @('Owner', 'Contributor') })) {
	throw 'Authenticated user should have the Owner/Contributor permissions to the subscription'
   }
   #>
   ```

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 새 탭을 열고 다음 스크립트를 붙여넣은 다음 실행하여 자동 크기 조정 솔루션의 일부분인 Azure Automation 계정을 만듭니다.

   ```powershell
   $Params = @{
     "AADTenantId" = $aadTenantId
     "SubscriptionId" = $subscriptionId 
     "UseARMAPI" = $true
     "ResourceGroupName" = $resourceGroupName
     "AutomationAccountName" = $automationAccountName
     "Location" = $location
     "WorkspaceName" = $workspaceName
   }

   [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
   .\CreateOrUpdateAzAutoAccount.ps1 @Params
   ```

   >**참고**: 스크립트가 완료될 때까지 기다립니다. 완료되려면 10분 정도 걸립니다.

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 스크립트 출력을 검토합니다. 

   >**참고**: 출력에는 웹후크 URI, Log Analytics 작업 영역 Id, 그리고 자동 크기 조정 솔루션의 일부분인 Azure Logic App을 프로비전할 때 제공해야 하는 해당 기본 키 값이 포함되어 있습니다.

1. Azure Automation 계정의 구성을 확인하려면 **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내에서 Microsoft Edge를 시작하고 [Azure Portal](https://portal.azure.com)로 이동합니다. 메시지가 표시되면 이 랩에서 사용 중인 구독의 Owner 역할이 할당된 사용자 계정의 Azure AD 자격 증명을 사용하여 로그인합니다.
1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 Azure Portal이 표시된 Microsoft Edge 창에서 **Automation 계정**을 검색하여 선택합니다. 그런 다음 **Automation 계정** 블레이드에서 새로 프로비전된 Azure Automation 계정에 해당하는 항목(**az140-automation-51** 접두사로 시작되는 항목)을 선택합니다.
1. Automation 계정 블레이드 왼쪽의 세로 메뉴에 있는 **프로세스 자동화** 섹션에서 **Runbook**을 선택하고 Runbook 목록에서 **WVDAutoScaleRunbookARMBased** Runbook이 있는지 확인합니다.
1. Automation 계정 블레이드 왼쪽의 세로 메뉴에 있는 **계정 설정** 섹션에서 **실행 계정**을 선택하고 오른쪽의 계정 목록에서 **Azure 실행 계정** 옆에 있는 **+ 만들기**를 클릭합니다.
1. **Azure 실행 계정 만들기** 블레이드에서 **만들기**를 클릭하고 새 계정이 정상적으로 작성되었는지 확인합니다.

#### 작업 3: Azure 논리 앱 만들기

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내에서 **관리자: Windows PowerShell ISE** 창으로 전환한 다음 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 자동 크기 조정 솔루션의 일부분인 Azure 논리 앱을 만드는 데 사용할 PowerShell 스크립트를 다운로드합니다.

   ```powershell
   $labFilesfolder = 'C:\Allfiles\Labs\05'
   Set-Location -Path $labFilesfolder
   $uri = "https://raw.githubusercontent.com/Azure/RDS-Templates/master/wvd-templates/wvd-scaling-script/CreateOrUpdateAzLogicApp.ps1"
   Invoke-WebRequest -Uri $uri -OutFile ".\CreateOrUpdateAzLogicApp.ps1"
   ```

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE**에서 **C:\\Allfiles\\Labs\\05\\CreateOrUpdateAzLogicApp.ps1** 스크립트를 열고 줄 **134**와 **138** 사이의 코드를 다음과 같이 여러 줄 주석으로 설정합니다.

   ```powershell
   <#
   # 인증된 사용자의 역할 할당 가져오기
   $RoleAssignments = Get-AzRoleAssignment -SignInName $AzContext.Account -ExpandPrincipalGroups
   if (!($RoleAssignments | Where-Object { $_.RoleDefinitionName -in @('Owner', 'Contributor') })) {
	throw 'Authenticated user should have the Owner/Contributor permissions to the subscription'
   }
   #>
   ```

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 스크립트 매개 변수에 할당할 변수의 값을 설정합니다.

   ```powershell
   $AADTenantId = (Get-AzContext).Tenant.Id
   $AzSubscription = (Get-AzContext).Subscription.Id
   $ResourceGroup = Get-AzResourceGroup -Name 'az140-51-RG'
   $WVDHostPool = Get-AzResource -ResourceType "Microsoft.DesktopVirtualization/hostpools" -Name 'az140-21-hp1'
   $LogAnalyticsWorkspace = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroup.ResourceGroupName)[0]
   $LogAnalyticsWorkspaceId = $LogAnalyticsWorkspace.CustomerId
   $LogAnalyticsWorkspaceKeys = (Get-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $ResourceGroup.ResourceGroupName -Name $LogAnalyticsWorkspace.Name)
   $LogAnalyticsPrimaryKey = $LogAnalyticsWorkspaceKeys.PrimarySharedKey
   $RecurrenceInterval = 2
   $BeginPeakTime = '1:00'
   $EndPeakTime = '1:01'
   $TimeDifference = '0:00'
   $SessionThresholdPerCPU = 1
   $MinimumNumberOfRDSH = 1
   $MaintenanceTagName = 'CustomMaintenance'
   $LimitSecondsToForceLogOffUser = 5
   $LogOffMessageTitle = 'Autoscaling'
   $LogOffMessageBody = 'Forcing logoff due to autoscaling'

   $AutoAccount = (Get-AzAutomationAccount -ResourceGroupName $ResourceGroup.ResourceGroupName)[0]
   $AutoAccountConnection = Get-AzAutomationConnection -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName

   $WebhookURIAutoVar = Get-AzAutomationVariable -Name 'WebhookURIARMBased' -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName    $AutoAccount.AutomationAccountName
   ```

   >**참고**: 자동 크기 조정 동작 속도를 높일 수 있는 매개 변수 값이 설정됩니다. 프로덕션 환경에서는 구체적인 요구 사항과 일치하도록 매개 변수 값을 조정해야 합니다.

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 **관리자: Windows PowerShell ISE** 스크립트 창에서 다음 명령을 실행하여 자동 크기 조정 솔루션의 일부분인 Azure 논리 앱을 만듭니다.

   ```powershell
   $Params = @{
     "AADTenantId"                   = $AADTenantId                             # Optional. If not specified, it will use the current Azure context
     "SubscriptionID"                = $AzSubscription.Id                       # Optional. If not specified, it will use the current Azure context
     "ResourceGroupName"             = $ResourceGroup.ResourceGroupName         # Optional. Default: "WVDAutoScaleResourceGroup"
     "Location"                      = $ResourceGroup.Location                  # Optional. Default: "West US2"
     "UseARMAPI"                     = $true
     "HostPoolName"                  = $WVDHostPool.Name
     "HostPoolResourceGroupName"     = $WVDHostPool.ResourceGroupName           # Optional. Default: same as ResourceGroupName param value
     "LogAnalyticsWorkspaceId"       = $LogAnalyticsWorkspaceId                 # Optional. If not specified, script will not log to the Log Analytics
     "LogAnalyticsPrimaryKey"        = $LogAnalyticsPrimaryKey                  # Optional. If not specified, script will not log to the Log Analytics
     "ConnectionAssetName"           = $AutoAccountConnection.Name              # Optional. Default: "AzureRunAsConnection"
     "RecurrenceInterval"            = $RecurrenceInterval                      # Optional. Default: 15
     "BeginPeakTime"                 = $BeginPeakTime                           # Optional. Default: "09:00"
     "EndPeakTime"                   = $EndPeakTime                             # Optional. Default: "17:00"
     "TimeDifference"                = $TimeDifference                          # Optional. Default: "-7:00"
     "SessionThresholdPerCPU"        = $SessionThresholdPerCPU                  # Optional. Default: 1
     "MinimumNumberOfRDSH"           = $MinimumNumberOfRDSH                     # Optional. Default: 1
     "MaintenanceTagName"            = $MaintenanceTagName                      # Optional.
     "LimitSecondsToForceLogOffUser" = $LimitSecondsToForceLogOffUser           # Optional. Default: 1
     "LogOffMessageTitle"            = $LogOffMessageTitle                      # Optional. Default: "Machine is about to shut down."
     "LogOffMessageBody"             = $LogOffMessageBody                       # Optional. Default: "Your session will be logged off. Please save and close everything."
     "WebhookURI"                    = $WebhookURIAutoVar.Value
   }

   .\CreateOrUpdateAzLogicApp.ps1 @Params
   ```

   >**참고**: 스크립트가 완료될 때까지 기다립니다. 완료되려면 2분 정도 걸립니다.

1. Azure 논리 앱의 구성을 확인하려면 **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 Azure Portal이 표시된 Microsoft Edge 창으로 전환한 후 **논리 앱**을 검색하여 선택합니다. 그런 다음 **논리 앱** 블레이드에서 새로 프로비전된 Azure 논리 앱 **az140-21-hp1_Autoscale_Scheduler**에 해당하는 항목을 선택합니다.
1. **az140-21-hp1_Autoscale_Scheduler** 블레이드 왼쪽의 세로 메뉴에 있는 **개발 도구** 섹션에서 **논리 앱 디자이너**를 선택합니다. 
1. 디자이너 창에서 레이블이 **되풀이**인 사각형을 클릭하여 자동 크기 조정을 평가해야 하는 빈도를 제어하는 데 이 옵션을 사용할 수 있음을 확인합니다. 

### 연습 2: Azure Virtual Desktop 세션 호스트의 자동 크기 조정 확인 및 검토

이 연습의 주요 작업은 다음과 같습니다.

1. Azure Virtual Desktop 세션 호스트의 자동 크기 조정 확인
1. Azure Log Analytics를 사용하여 Azure Virtual Desktop 이벤트 추적

#### 작업 1: Azure Virtual Desktop 세션 호스트의 자동 크기 조정 확인

1. Azure Desktop 세션 호스트의 자동 크기 조정을 확인하려면 **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 Azure Portal이 표시된 Microsoft Edge 창에서 **가상 머신**을 검색하여 선택합니다. 그런 다음 **가상 머신** 블레이드에서 **az140-21-RG** 리소스 그룹 내 Azure VM 3개의 상태를 검토합니다.
1. Azure VM 3개 중 2개는 할당 취소 중이거나 이미 **중지됨(할당 취소됨)** 상태임을 확인합니다.

   >**참고**: 자동 크기 조정이 작동함을 확인하는 즉시 해당 요금을 최소화할 수 있도록 Azure 논리 앱을 사용하지 않도록 설정해야 합니다.

1. Azure 논리 앱을 사용하지 않도록 설정하려면 **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 Azure Portal이 표시된 Microsoft Edge 창에서 **논리 앱**을 검색하여 선택합니다. 그런 다음 **논리 앱** 블레이드에서 새로 프로비전된 Azure 논리 앱 **az140-21-hp1_Autoscale_Scheduler**에 해당하는 항목을 선택합니다.
1. **az140-21-hp1_Autoscale_Scheduler** 블레이드의 도구 모음에서 **사용 안 함**을 선택합니다. 
1. **az140-21-hp1_Autoscale_Scheduler** 블레이드의 **필수** 섹션에서 지난 24시간 동안의 정상 실행 횟수, 그리고 되풀이 빈도를 확인할 수 있는 **요약** 섹션 등의 정보를 검토합니다. 
1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 Azure Portal이 표시된 Microsoft Edge 창에서 **Automation 계정**을 검색하여 선택합니다. 그런 다음 **Automation 계정** 블레이드에서 새로 프로비전된 Azure Automation 계정에 해당하는 항목(**az140-automation-51** 접두사로 시작되는 항목)을 선택합니다.
1. **Automation 계정** 블레이드 왼쪽의 세로 메뉴에 있는 **프로세스 자동화** 섹션에서 **작업**을 선택하고 **WVDAutoScaleRunbookARMBased** Runbook의 개별 호출에 해당하는 작업 목록을 검토합니다.
1. 가장 최근 작업을 선택하고 해당 작업의 블레이드에서 **모든 로그** 탭 머리글을 클릭합니다. 그러면 작업 실행 단계의 세부 목록이 표시됩니다.

#### 작업 2: Azure Log Analytics를 사용하여 Azure Virtual Desktop 이벤트 추적

>**참고**: 자동 크기 조정 및 다른 Azure Virtual Desktop 이벤트를 분석하려는 경우 Log Analytics를 사용할 수 있습니다.

1. **az140-dc-vm11**에 연결된 원격 데스크톱 세션 내의 Azure Portal이 표시된 Microsoft Edge 창에서 **Log Analytics 작업 영역**을 검색하여 선택합니다. 그런 다음 **Log Analytics 작업 영역** 블레이드에서 이 랩에서 사용하는 Azure Log Analytics 작업 영역에 해당하는 항목(이름이 **az140-workspace-51** 접두사로 시작되는 항목)을 선택합니다.
1. Log Analytics 작업 영역 블레이드 왼쪽의 세로 메뉴에 있는 **일반** 섹션에서 **로그**를 클릭하고, 필요한 경우 **Log Analytics 시작** 창울 닫습니다. 그런 후에 **쿼리** 창으로 진행합니다.
1. **쿼리** 창 왼쪽의 **모든 쿼리** 세로 메뉴에서 **Azure Virtual Desktop**을 선택하고 미리 정의된 쿼리를 검토합니다.
1. **쿼리** 창을 닫습니다. 그러면 **새 쿼리 1** 탭이 자동으로 표시됩니다.
1. 쿼리 창에 다음 쿼리를 붙여넣고 **실행**을 클릭하여 이 랩에서 사용하는 호스트 풀의 모든 이벤트를 표시합니다.

   ```kql
   WVDTenantScale_CL
   | where hostpoolName_s == "az140-21-hp1"
   | project TimeStampUTC = TimeGenerated, TimeStampLocal = TimeStamp_s, HostPool = hostpoolName_s, LineNumAndMessage = logmessage_s, AADTenantId = TenantId
   ```

   >**참고**: 결과가 표시되지 않으면 몇 분 기다린 후 다시 시도합니다.

1. 쿼리 창에 다음 쿼리를 붙여넣고 **실행**을 클릭하여 대상 호스트 풀의 활성 사용자 세션 및 현재 실행 중인 세션 호스트의 총 수를 표시합니다.

   ```kql
   WVDTenantScale_CL
   | where logmessage_s contains "Number of running session hosts:"
     or logmessage_s contains "Number of user sessions:"
     or logmessage_s contains "Number of user sessions per Core:"
   | where hostpoolName_s == "az140-21-hp1"
   | project TimeStampUTC = TimeGenerated, TimeStampLocal = TimeStamp_s, HostPool = hostpoolName_s, LineNumAndMessage = logmessage_s, AADTenantId = TenantId
   ```

1. 쿼리 창에 다음 쿼리를 붙여넣고 **실행**을 클릭하여 호스트 풀의 모든 세션 호스트 VM 상태를 표시합니다.

   ```kql
   WVDTenantScale_CL
   | where logmessage_s contains "Session host:"
   | where hostpoolName_s == "az140-21-hp1"
   | project TimeStampUTC = TimeGenerated, TimeStampLocal = TimeStamp_s, HostPool = hostpoolName_s, LineNumAndMessage = logmessage_s, AADTenantId = TenantId
   ```

1. 쿼리 창에 다음 쿼리를 붙여넣고 **실행**을 클릭하여 크기 조정 관련 오류 및 경고를 표시합니다.

   ```kql
   WVDTenantScale_CL
   | where logmessage_s contains "ERROR:" or logmessage_s contains "WARN:"
   | project TimeStampUTC = TimeGenerated, TimeStampLocal = TimeStamp_s, HostPool = hostpoolName_s, LineNumAndMessage = logmessage_s, AADTenantId = TenantId
   ```

>**참고**: `TenantId`와 관련된 오류 메시지는 무시하세요.

### 연습 3: 랩에서 프로비전한 Azure VM 중지 및 할당 취소

이 연습의 주요 작업은 다음과 같습니다.

1. 랩에서 프로비전한 Azure VM 중지 및 할당 취소

>**참고**: 이 연습에서는 해당 컴퓨팅 비용을 최소화하기 위해 이 랩에서 프로비전한 Azure VM의 할당을 취소합니다.

#### 작업 1: 랩에서 프로비전한 Azure VM 할당 취소

1. 랩 컴퓨터로 전환한 다음 Azure Portal이 표시된 웹 브라우저 창에서 **Cloud Shell** 창 내에 **PowerShell** 셸 세션을 엽니다.
1. Cloud Shell 창 내의 PowerShell 세션에서 다음 명령을 실행하여 이 랩에서 만든 모든 Azure VM의 목록을 표시합니다.

   ```powershell
   Get-AzVM -ResourceGroup 'az140-21-RG'
   ```

1. Cloud Shell 창의 PowerShell 세션에서 다음 명령을 실행하여 이 랩에서 만든 모든 Azure VM을 중지하고 할당을 취소합니다.

   ```powershell
   Get-AzVM -ResourceGroup 'az140-21-RG' | Stop-AzVM -NoWait -Force
   ```

   >**참고**: 명령은 비동기적으로 실행되므로(-NoWait 매개 변수에 의해 결정됨) 동일한 PowerShell 세션 내에서 즉시 다른 PowerShell 명령을 실행할 수는 있지만, Azure VM이 실제로 중지 및 할당 취소되려면 몇 분 정도 걸립니다.
