package com.p3solutions.archon_authentication_service.core.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.p3solutions.common_beans_dto.audit.dto.request.AuditRequestDTO;
import com.p3solutions.common_beans_dto.audit.enums.Category;
import com.p3solutions.common_beans_dto.audit.enums.Event;
import com.p3solutions.common_beans_dto.audit.enums.EventType;
import com.p3solutions.common_beans_dto.common_beans.KafkaMessenger;
import com.p3solutions.kafka.messengers.Messenger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuditHelper {
    //	@Autowired
//	private MicroserviceInstanceService dsService;
    @Autowired
    private Messenger messageProducer;
//	@Autowired
//	private WorkspaceRepository repository;
//	@Autowired
//	private DatabaseConfigurationRepository databaseRepository;
//	@Autowired
//	private CommonJobRepository commonJobRepository;

    public void LogEvents(String userId, Event event, String eventDetails, Boolean isSystemDriven) {

        try {
            // List<ServiceInstance> serviceList =
            // dsService.serviceInstance("common-backend");

            // ServiceInstance service = serviceList.get(0);

            AuditRequestDTO auditInput = AuditRequestDTO.builder().userId(userId).event(event)
                    .category(Category.valueOf(event.getCategory())).eventType(EventType.valueOf(event.getEventType()))
                    .eventDetails(eventDetails).eventType(EventType.valueOf(event.getEventType()))
                    .systemDriven(isSystemDriven).build();
            ObjectMapper mapper = new ObjectMapper();
            KafkaMessenger messenger = KafkaMessenger.builder().jobInput(mapper.writeValueAsString(auditInput)).build();
            messageProducer.send("AUDITING", event.getEventType(), messenger);
        } catch (JsonProcessingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

//	public void LogEventsData(String userId, Event event, String eventDetails, Boolean isSystemDriven,
//			String workspaceId, String datasourceId, String jobId) throws GenericExceptionC {
//
//		try {
//			// List<ServiceInstance> serviceList =
//			// dsService.serviceInstance("common-backend");
//
//			// ServiceInstance service = serviceList.get(0);
//			WorkspaceDetails wsDetils = null;
//			DataSourceDetails dsDetails = null;
//			RelatedJobDetails relatedJobDetails = null;
//
//			if (workspaceId != null) {
//				WorkspaceModel workspaceModel = repository.findById(workspaceId)
//						.orElseThrow(() -> new GenericExceptionC("Invalid workspace provided for audit"));
//				wsDetils = WorkspaceDetails.builder().workspaceID(workspaceModel.getId())
//						.WorkspaceName(workspaceModel.getWorkspaceName()).build();
//			}
//			if (datasourceId != null) {
//				DatabaseConfigurationModel databaseModel = databaseRepository.findById(datasourceId)
//						.orElseThrow(() -> new GenericExceptionC("Invalid dataSource provided for audit"));
//				dsDetails = DataSourceDetails.builder().dataSourceID(databaseModel.getId())
//						.dataSourceName(databaseModel.getDatabaseName()).build();
//			}
//			if (jobId != null) {
//				JobListModel jobModel = commonJobRepository.findById(jobId)
//						.orElseThrow(() -> new GenericExceptionC("Invalid job provided for audit"));
//				relatedJobDetails = RelatedJobDetails.builder().jobid(jobModel.getId()).jobName(jobModel.getJobName())
//						.build();
//			}
//
//			AuditInput auditInput = AuditInput.builder().userId(userId).event(event)
//					.category(Category.valueOf(event.getCategory())).eventType(EventType.valueOf(event.getEventType()))
//					.eventDetails(eventDetails).eventType(EventType.valueOf(event.getEventType()))
//					.systemDriven(isSystemDriven).build();
//			if (wsDetils != null) {
//				auditInput.setWorkspaceDetails(wsDetils);
//			}
//			if (dsDetails != null) {
//				auditInput.setDataSourcedetails(dsDetails);
//			}
//			if (relatedJobDetails != null) {
//				auditInput.setRelatedJobDetails(relatedJobDetails);
//			}
//			ObjectMapper mapper = new ObjectMapper();
//			KafkaMessenger messenger = KafkaMessenger.builder().jobInput(mapper.writeValueAsString(auditInput)).build();
//			messageProducer.caller("AUDITING", messenger, messenger);
//		} catch (JsonProcessingException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//	}
    /*
     * public void LogEvents(String userId, AuditEvents event, String workspaceId,
     * String eventDetails) {
     *
     * try { // List<ServiceInstance> serviceList = //
     * dsService.serviceInstance("common-backend");
     *
     * // ServiceInstance service = serviceList.get(0);
     *
     * AuditInput auditInput =
     * AuditInput.builder().userId(userId).eventName(event.toString())
     * .eventDescription(event.getDesc()).eventDetails(eventDetails) //
     * .serviceId(service.getServiceId()).serverIpAddress(service.getHost()).port(
     * service.getPort())
     * .severityLevel(event.getSev()).eventType(event.getType()).build();
     * ObjectMapper mapper = new ObjectMapper(); KafkaMessenger messenger =
     * KafkaMessenger.builder().jobInput(mapper.writeValueAsString(auditInput)).
     * build(); messageProducer.caller("AUDITING", messenger, messenger); } catch
     * (JsonProcessingException e) { // TODO Auto-generated catch block
     * e.printStackTrace(); } }
     */

    /*
     * public void LogEvents(String userId, AuditEvents event, String workspaceId,
     * String releatedJobId, String eventDetails) {
     *
     * try { // List<ServiceInstance> serviceList = //
     * dsService.serviceInstance("common-backend");
     *
     * // ServiceInstance service = serviceList.get(0);
     *
     * AuditInput auditInput =
     * AuditInput.builder().userId(userId).eventName(event.toString())
     * .eventDescription(event.getDesc()).eventDetails(eventDetails).releatedJobId(
     * releatedJobId) //
     * .serviceId(service.getServiceId()).serverIpAddress(service.getHost()).port(
     * service.getPort())
     * .severityLevel(event.getSev()).eventType(event.getType()).build();
     * ObjectMapper mapper = new ObjectMapper(); KafkaMessenger messenger =
     * KafkaMessenger.builder().jobInput(mapper.writeValueAsString(auditInput)).
     * build(); messageProducer.caller("AUDITING", messenger, messenger); } catch
     * (JsonProcessingException e) { // TODO Auto-generated catch block
     * e.printStackTrace(); } }
     */
}
