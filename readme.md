**Important Notice!**

This repo was replaced by a [new repo](https://github.com/MicrosoftLearning/AZ-140-Configuring-and-Operating-Microsoft-Azure-Virtual-Desktop.ko-kr) on 4 February 2022 . We're making this change to improve the localized version of this content and reduce the delta between English and localized content updates. 
After a short interval, this repo will be archived.

**Contributions**

At this time, we are not accepting external contributions to this repo. If you have suggestions or spot any errors, please create a pull request or report an issue on the [new repo](https://github.com/MicrosoftLearning/AZ-140-Configuring-and-Operating-Microsoft-Azure-Virtual-Desktop.ko-kr).
# AZ-140: Microsoft Azure Virtual Desktop 구성 및 작동

- **[최신 학생용 핸드북 및 AllFiles 콘텐츠 다운로드](../../releases/latest)**
- **MCT인가요?** - [MCT용 GitHub 사용자 가이드](https://microsoftlearning.github.io/MCT-User-Guide-KO/)를 살펴보세요.
- **랩 명령을 수동으로 빌드해야 합니까?** - [MicrosoftLearning/Docker-Build](https://github.com/MicrosoftLearning/Docker-Build) 리포지토리에서 명령을 사용할 수 있습니다.

## Microsoft의 역할

- 이 과정을 지원하려면 해당 과정에 사용된 Azure 서비스를 최신 상태로 유지하기 위해 과정 콘텐츠를 자주 업데이트해야 합니다.  GitHub에 랩 지침 및 랩 파일을 게시하여 과정 작성자 및 MCT 간의 공개적인 기여를 통해 Azure 플랫폼의 변경 내용에 따라 콘텐츠를 최신 상태로 유지하도록 합니다.

- 여러분도 이와 같은 새로운 공동 작업 방식 랩 개선 과정에 참여하실 수 있습니다. 실제 강의를 진행하는 과정에서 Azure의 변경 내용을 처음으로 확인하시는 분은 랩 원본을 바로 개선해 주시기 바랍니다.  그러면 다른 MCT가 랩을 더욱 효율적으로 진행할 수 있습니다.

## 릴리스된 MOC 파일과 비교하여 이러한 파일을 사용하려면 어떻게 해야 합니까?

- 강사 핸드북과 PowerPoint는 여전히 과정 콘텐츠를 가르치는 기본적인 자료로 사용될 것입니다.

- GitHub의 이러한 파일은 수강생 핸드북과 함께 사용할 수 있도록 설계되었지만 중앙 리포지토리 역할을 하는 GitHub에 위치합니다. 따라서 MCT와 과정 작성자가 최신 랩 파일에 대한 소스를 공유할 수 있습니다.

- 트레이너는 각 강의를 제공할 때마다 GitHub에서 최신 Azure 서비스를 지원하기 위해 변경된 내용을 확인하고 최신 파일을 가져와서 강의에 사용하는 것이 좋습니다.

## 수강생 핸드북의 변경 사항은 어떻게 되나요?

- 수강생 핸드북은 분기별로 검토되며 필요에 따라 일반 MOC 릴리스 채널을 통해 업데이트됩니다.

## 기고하려면 어떻게 해야 합니까?

- 모든 MCT는 GitHub 리포지토리의 코드 또는 콘텐츠에 대한 끌어오기 요청을 제출할 수 있습니다. Microsoft와 과정 작성자는 콘텐츠 및 랩 코드 변경을 선별하고 필요에 따라 포함합니다.

- MCT는 버그, 변경 사항, 개선 사항 및 아이디어를 제출할 수 있습니다.  Microsoft보다 먼저 새로운 Azure 기능을 찾았다면  새로운 데모를 제출해 주세요!

## 참고

**이 랩은 사용하기로 결정한 ID 공급자에 따라 2개의 별도 트랙으로 구성됩니다.**

- AD DS(Active Directory Domain Services) 이 트랙은 다음과 같은 랩으로 구성됩니다.

   - LAB_01L01_Prepare_for_deployment_of_AVD_ADDS.md
   - LAB_02L01_Deploy_host_pools_and_session_hosts_with_the_Azure_portal_ADDS.md
   - LAB_02L02_Implement_and_manage_storage_for_AVD_ADDS.md
   - LAB_02L03_Deploy_host_pools_and_hosts_with_ARM_templates_ADDS.md
   - LAB_02L04_Deploy_and_manage_host_pools_and_hosts_with_PowerShell_ADDS.md
   - LAB_02L05_Create_and_manage_session_host_images_ADDS.md
   - LAB_03L01_Configure_Conditional_Access_policies_for_AVD_ADDS.md
   - LAB_04L01_Implement_and_manage_AVD_profiles_ADDS.md
   - LAB_04L02_Package_AVD_applications_ADDS.md
   - LAB_05L01_Implement_autoscaling_in_host_pools_ADDS.md

- Azure AD DS(Azure Active Directory Domain Services). 이 트랙은 다음과 같은 랩으로 구성됩니다.

   - LAB_01L01_Prepare_for_deployment_of_AVD_AADDS.md
   - LAB_02L01_Create_and_configure_host_pools_and_session_hosts_AADDS.md
   - LAB_02L02_Implement_and_manage_storage_for_AVD_AADDS.md
   - LAB_04L01_Implement_and_manage_AVD_profiles_AADDS.md

### 강의 자료

MCT와 파트너는 이러한 자료에 액세스하고 수강생에게 개별적으로 제공하는 것이 좋습니다.  수업 진행 중에 수강생에게 GitHub 랩 단계를 직접 액세스하도록 하면 과정의 일부로 다른 UI에 액세스해야 하므로 수강생이 혼란을 겪을 수 있습니다. 수강생에게 별도의 랩 지침을 사용해야 하는 이유를 설명하면 계속 변경되는 클라우드 기반 인터페이스 및 플랫폼의 특성을 강조하는 데 도움이 됩니다. GitHub 파일 액세스와 GitHub 사이트 탐색에 대한 Microsoft Learning 지원은 이 과정을 가르치는 MCT에게만 제공됩니다.
