-- drop_network_tools_tables_and_indexes_explicit.sql
--
-- Purpose:
--   Explicitly drop constraints, indexes, and tables defined by 20_network_tools_schema.sql
--   for the *network_tools* database ONLY.
--
-- How to run (Docker):
--   docker exec -i postgres_primary sh -lc '
--     U="$(cat /run/vault/postgres_user)";
--     psql -U "$U" -d network_tools -v ON_ERROR_STOP=1
--   ' < drop_network_tools_tables_and_indexes_explicit.sql
--
-- Safety:
--   Refuses to run unless current_database() = 'network_tools'.

DO $$
BEGIN
  IF current_database() <> 'network_tools' THEN
    RAISE EXCEPTION 'Refusing to run: current_database() = %, expected network_tools', current_database();
  END IF;
END $$;

BEGIN;

-- ============================================================
-- Table: public.discovered_device_configuration_profiles
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.discovered_device_configuration_profiles DROP CONSTRAINT IF EXISTS discovered_device_configuration_profiles__pk;
ALTER TABLE IF EXISTS public.discovered_device_configuration_profiles DROP CONSTRAINT IF EXISTS discovered_device_configuration_profiles_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_discovered_device_configuration_profiles__ipv4_loopback;
DROP INDEX IF EXISTS public.idx_discovered_device_configuration_profiles__device_type;
DROP INDEX IF EXISTS public.idx_discovered_device_configuration_profiles__hostname;
DROP INDEX IF EXISTS public.idx_discovered_device_configuration_profiles__system_s_fca6e698;
DROP INDEX IF EXISTS public.idx_discovered_device_configuration_profiles__model_number;

-- Table
DROP TABLE IF EXISTS public.discovered_device_configuration_profiles CASCADE;

-- ============================================================
-- Table: public.access_list_statistics_table_processed
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.access_list_statistics_table_processed DROP CONSTRAINT IF EXISTS access_list_statistics_table_processed__pk;
ALTER TABLE IF EXISTS public.access_list_statistics_table_processed DROP CONSTRAINT IF EXISTS access_list_statistics_table_processed__data_type__uq;
ALTER TABLE IF EXISTS public.access_list_statistics_table_processed DROP CONSTRAINT IF EXISTS access_list_statistics_table_processed_pkey;

-- Table
DROP TABLE IF EXISTS public.access_list_statistics_table_processed CASCADE;

-- ============================================================
-- Table: public.circuit_install_technicians
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.circuit_install_technicians DROP CONSTRAINT IF EXISTS circuit_install_technicians__pk;
ALTER TABLE IF EXISTS public.circuit_install_technicians DROP CONSTRAINT IF EXISTS circuit_install_technicians_pkey;

-- Table
DROP TABLE IF EXISTS public.circuit_install_technicians CASCADE;

-- ============================================================
-- Table: public.wiring_database
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.wiring_database DROP CONSTRAINT IF EXISTS wiring_database__pk;
ALTER TABLE IF EXISTS public.wiring_database DROP CONSTRAINT IF EXISTS wiring_database_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_wiring_database__hub;
DROP INDEX IF EXISTS public.idx_wiring_database__port;
DROP INDEX IF EXISTS public.idx_wiring_database__port_type;
DROP INDEX IF EXISTS public.idx_wiring_database__department;
DROP INDEX IF EXISTS public.idx_wiring_database__originating_building;
DROP INDEX IF EXISTS public.idx_wiring_database__originating_room;
DROP INDEX IF EXISTS public.idx_wiring_database__trunk_cable;
DROP INDEX IF EXISTS public.idx_wiring_database__trunk_pair;
DROP INDEX IF EXISTS public.idx_wiring_database__terminating_building;
DROP INDEX IF EXISTS public.idx_wiring_database__station_cable;
DROP INDEX IF EXISTS public.idx_wiring_database__station_pair;
DROP INDEX IF EXISTS public.idx_wiring_database__install_order_number;
DROP INDEX IF EXISTS public.idx_wiring_database__change_order;
DROP INDEX IF EXISTS public.idx_wiring_database__technician;
DROP INDEX IF EXISTS public.idx_wiring_database__datetimestamp;
DROP INDEX IF EXISTS public.idx_wiring_database__requester;
DROP INDEX IF EXISTS public.idx_wiring_database__res_hall_service_number;
DROP INDEX IF EXISTS public.idx_wiring_database__res_hall_building;
DROP INDEX IF EXISTS public.idx_wiring_database__res_hall_cable_identifier;
DROP INDEX IF EXISTS public.idx_wiring_database__res_hall_remote_location;
DROP INDEX IF EXISTS public.idx_wiring_database__res_hall_nynex_cable_number;
DROP INDEX IF EXISTS public.idx_wiring_database__res_hall_cable_id;
DROP INDEX IF EXISTS public.idx_wiring_database__res_hall_cable_description;
DROP INDEX IF EXISTS public.idx_wiring_database__res_hall_purpose;
DROP INDEX IF EXISTS public.idx_wiring_database__res_hall_originating_location;
DROP INDEX IF EXISTS public.idx_wiring_database__res_hall_room_location;
DROP INDEX IF EXISTS public.idx_wiring_database__res_hall_room_location_code;
DROP INDEX IF EXISTS public.idx_wiring_database__res_hall_faceplate_position;
DROP INDEX IF EXISTS public.idx_wiring_database__res_hall_originating_tr;
DROP INDEX IF EXISTS public.idx_wiring_database__res_hall_vlan;
DROP INDEX IF EXISTS public.idx_wiring_database__circuit_id_status;
DROP INDEX IF EXISTS public.idx_wiring_database__hub_name;
DROP INDEX IF EXISTS public.idx_wiring_database__hub_ip;

-- Table
DROP TABLE IF EXISTS public.wiring_database CASCADE;

-- ============================================================
-- Table: public.ip_arp_table
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.ip_arp_table DROP CONSTRAINT IF EXISTS ip_arp_table__pk;
ALTER TABLE IF EXISTS public.ip_arp_table DROP CONSTRAINT IF EXISTS ip_arp_table_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_ip_arp_table__mac_address;
DROP INDEX IF EXISTS public.idx_ip_arp_table__device_name;
DROP INDEX IF EXISTS public.idx_ip_arp_table__ipv4_loopback;
DROP INDEX IF EXISTS public.idx_ip_arp_table__ipv4_address;
DROP INDEX IF EXISTS public.idx_ip_arp_table__interface_description;
DROP INDEX IF EXISTS public.idx_ip_arp_table__datetimestamp;

-- Table
DROP TABLE IF EXISTS public.ip_arp_table CASCADE;

-- ============================================================
-- Table: public.access_list_statistics_table
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.access_list_statistics_table DROP CONSTRAINT IF EXISTS access_list_statistics_table_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_access_list_statistics_table__ipv4_loopback;
DROP INDEX IF EXISTS public.idx_access_list_statistics_table__device_name;
DROP INDEX IF EXISTS public.idx_access_list_statistics_table__access_list_group;
DROP INDEX IF EXISTS public.idx_access_list_statistics_table__access_list_line;
DROP INDEX IF EXISTS public.idx_access_list_statistics_table__access_list_rule;
DROP INDEX IF EXISTS public.idx_access_list_statistics_table__datetimestamp;

-- Table
DROP TABLE IF EXISTS public.access_list_statistics_table CASCADE;

-- ============================================================
-- Table: public.device_mac_table_data
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.device_mac_table_data DROP CONSTRAINT IF EXISTS device_mac_table_data__pk;
ALTER TABLE IF EXISTS public.device_mac_table_data DROP CONSTRAINT IF EXISTS device_mac_table_data_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_device_mac_table_data__ipv4_loopback;
DROP INDEX IF EXISTS public.idx_device_mac_table_data__device_name;
DROP INDEX IF EXISTS public.idx_device_mac_table_data__information_type;
DROP INDEX IF EXISTS public.idx_device_mac_table_data__datetimestamp;

-- Table
DROP TABLE IF EXISTS public.device_mac_table_data CASCADE;

-- ============================================================
-- Table: public.switch_power_consumption
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.switch_power_consumption DROP CONSTRAINT IF EXISTS switch_power_consumption__pk;
ALTER TABLE IF EXISTS public.switch_power_consumption DROP CONSTRAINT IF EXISTS switch_power_consumption_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_switch_power_consumption__ipv4_loopback;
DROP INDEX IF EXISTS public.idx_switch_power_consumption__device_name;
DROP INDEX IF EXISTS public.idx_switch_power_consumption__chassis_model;
DROP INDEX IF EXISTS public.idx_switch_power_consumption__datetimestamp;

-- Table
DROP TABLE IF EXISTS public.switch_power_consumption CASCADE;

-- ============================================================
-- Table: public.software_transfer_status_que_history
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.software_transfer_status_que_history DROP CONSTRAINT IF EXISTS software_transfer_status_que_history__pk;
ALTER TABLE IF EXISTS public.software_transfer_status_que_history DROP CONSTRAINT IF EXISTS software_transfer_status_que_history_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_software_transfer_status_que_history__ipv4_loopback;
DROP INDEX IF EXISTS public.idx_software_transfer_status_que_history__status;
DROP INDEX IF EXISTS public.idx_software_transfer_status_que_history__file_name;

-- Table
DROP TABLE IF EXISTS public.software_transfer_status_que_history CASCADE;

-- ============================================================
-- Table: public.software_transfer_status_que
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.software_transfer_status_que DROP CONSTRAINT IF EXISTS software_transfer_status_que__pk;
ALTER TABLE IF EXISTS public.software_transfer_status_que DROP CONSTRAINT IF EXISTS software_transfer_status_que_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_software_transfer_status_que__ipv4_loopback;
DROP INDEX IF EXISTS public.idx_software_transfer_status_que__status;
DROP INDEX IF EXISTS public.idx_software_transfer_status_que__model_number;
DROP INDEX IF EXISTS public.idx_software_transfer_status_que__info_progress;
DROP INDEX IF EXISTS public.idx_software_transfer_status_que__file_name;

-- Table
DROP TABLE IF EXISTS public.software_transfer_status_que CASCADE;

-- ============================================================
-- Table: public.software_transfer_status
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.software_transfer_status DROP CONSTRAINT IF EXISTS software_transfer_status__pk;
ALTER TABLE IF EXISTS public.software_transfer_status DROP CONSTRAINT IF EXISTS software_transfer_status__uq_status_loopback_filename__uq;
ALTER TABLE IF EXISTS public.software_transfer_status DROP CONSTRAINT IF EXISTS software_transfer_status_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_software_transfer_status__ipv4_loopback;
DROP INDEX IF EXISTS public.idx_software_transfer_status__status;
DROP INDEX IF EXISTS public.idx_software_transfer_status__file_name;
DROP INDEX IF EXISTS public.idx_software_transfer_status__model_number;
DROP INDEX IF EXISTS public.idx_software_transfer_status__info_progress;

-- Table
DROP TABLE IF EXISTS public.software_transfer_status CASCADE;

-- ============================================================
-- Table: public.vault_information_archive
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.vault_information_archive DROP CONSTRAINT IF EXISTS vault_information_archive__pk;
ALTER TABLE IF EXISTS public.vault_information_archive DROP CONSTRAINT IF EXISTS vault_information_archive_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_vault_information_archive__path;
DROP INDEX IF EXISTS public.idx_vault_information_archive__key_name;

-- Table
DROP TABLE IF EXISTS public.vault_information_archive CASCADE;

-- ============================================================
-- Table: public.vault_information
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.vault_information DROP CONSTRAINT IF EXISTS vault_information__pk;
ALTER TABLE IF EXISTS public.vault_information DROP CONSTRAINT IF EXISTS vault_information_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_vault_information__path;
DROP INDEX IF EXISTS public.idx_vault_information__key_name;

-- Table
DROP TABLE IF EXISTS public.vault_information CASCADE;

-- ============================================================
-- Table: public.UserTable
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public."UserTable" DROP CONSTRAINT IF EXISTS "UserTable__pk";
ALTER TABLE IF EXISTS public."UserTable" DROP CONSTRAINT IF EXISTS "UserTable_pkey";

-- Table
DROP TABLE IF EXISTS public."UserTable" CASCADE;

-- ============================================================
-- Table: public.templates_history
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.templates_history DROP CONSTRAINT IF EXISTS templates_history__pk;
ALTER TABLE IF EXISTS public.templates_history DROP CONSTRAINT IF EXISTS templates_history_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_templates_history__template_name;
DROP INDEX IF EXISTS public.idx_templates_history__attached_to_device;
DROP INDEX IF EXISTS public.idx_templates_history__function;

-- Table
DROP TABLE IF EXISTS public.templates_history CASCADE;

-- ============================================================
-- Table: public.templates_development
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.templates_development DROP CONSTRAINT IF EXISTS templates_development__pk;
ALTER TABLE IF EXISTS public.templates_development DROP CONSTRAINT IF EXISTS templates_development__template_name__uq;
ALTER TABLE IF EXISTS public.templates_development DROP CONSTRAINT IF EXISTS templates_development_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_templates_development__attached_to_device;
DROP INDEX IF EXISTS public.idx_templates_development__function;

-- Table
DROP TABLE IF EXISTS public.templates_development CASCADE;

-- ============================================================
-- Table: public.templates_deleted
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.templates_deleted DROP CONSTRAINT IF EXISTS templates_deleted__pk;
ALTER TABLE IF EXISTS public.templates_deleted DROP CONSTRAINT IF EXISTS templates_deleted_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_templates_deleted__template_name;
DROP INDEX IF EXISTS public.idx_templates_deleted__attached_to_device;
DROP INDEX IF EXISTS public.idx_templates_deleted__function;

-- Table
DROP TABLE IF EXISTS public.templates_deleted CASCADE;

-- ============================================================
-- Table: public.templates_active
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.templates_active DROP CONSTRAINT IF EXISTS templates_active__pk;
ALTER TABLE IF EXISTS public.templates_active DROP CONSTRAINT IF EXISTS templates_active__template_name__uq;
ALTER TABLE IF EXISTS public.templates_active DROP CONSTRAINT IF EXISTS templates_active_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_templates_active__attached_to_device;
DROP INDEX IF EXISTS public.idx_templates_active__function;

-- Table
DROP TABLE IF EXISTS public.templates_active CASCADE;

-- ============================================================
-- Table: public.site_location_information
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.site_location_information DROP CONSTRAINT IF EXISTS site_location_information__pk;
ALTER TABLE IF EXISTS public.site_location_information DROP CONSTRAINT IF EXISTS site_location_information__site_id__uq;
ALTER TABLE IF EXISTS public.site_location_information DROP CONSTRAINT IF EXISTS site_location_information_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_site_location_information__location_name;
DROP INDEX IF EXISTS public.idx_site_location_information__street_address;
DROP INDEX IF EXISTS public.idx_site_location_information__city;
DROP INDEX IF EXISTS public.idx_site_location_information__postal_code;
DROP INDEX IF EXISTS public.idx_site_location_information__country;
DROP INDEX IF EXISTS public.idx_site_location_information__datetimestamp;

-- Table
DROP TABLE IF EXISTS public.site_location_information CASCADE;

-- ============================================================
-- Table: public.reporting_cisco_api_eox
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.reporting_cisco_api_eox DROP CONSTRAINT IF EXISTS reporting_cisco_api_eox__pk;
ALTER TABLE IF EXISTS public.reporting_cisco_api_eox DROP CONSTRAINT IF EXISTS reporting_cisco_api_eox_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_reporting_cisco_api_eox__datetimestamp;

-- Table
DROP TABLE IF EXISTS public.reporting_cisco_api_eox CASCADE;

-- ============================================================
-- Table: public.reporting_cisco_api_cve_software
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.reporting_cisco_api_cve_software DROP CONSTRAINT IF EXISTS reporting_cisco_api_cve_software__pk;
ALTER TABLE IF EXISTS public.reporting_cisco_api_cve_software DROP CONSTRAINT IF EXISTS reporting_cisco_api_cve_software_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_reporting_cisco_api_cve_software__datetimestamp;

-- Table
DROP TABLE IF EXISTS public.reporting_cisco_api_cve_software CASCADE;

-- ============================================================
-- Table: public.production_device_provisioning_repository
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.production_device_provisioning_repository DROP CONSTRAINT IF EXISTS production_device_provisioning_repository__pk;
ALTER TABLE IF EXISTS public.production_device_provisioning_repository DROP CONSTRAINT IF EXISTS production_device_provisioning_repository__device_host_name__uq;
ALTER TABLE IF EXISTS public.production_device_provisioning_repository DROP CONSTRAINT IF EXISTS production_device_provisioning_repository_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_production_device_provisioning_repository__assigned_hub_id;
DROP INDEX IF EXISTS public.idx_production_device_provisioning_repository__device_65c3cb09;
DROP INDEX IF EXISTS public.idx_production_device_provisioning_repository__management_ip;
DROP INDEX IF EXISTS public.idx_production_device_provisioning_repository__managem_f6b4c6a6;
DROP INDEX IF EXISTS public.idx_production_device_provisioning_repository__datetimestamp;

-- Table
DROP TABLE IF EXISTS public.production_device_provisioning_repository CASCADE;

-- ============================================================
-- Table: public.new_device_provisioning_repository
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.new_device_provisioning_repository DROP CONSTRAINT IF EXISTS new_device_provisioning_repository__pk;
ALTER TABLE IF EXISTS public.new_device_provisioning_repository DROP CONSTRAINT IF EXISTS new_device_provisioning_repository__device_host_name__uq;
ALTER TABLE IF EXISTS public.new_device_provisioning_repository DROP CONSTRAINT IF EXISTS new_device_provisioning_repository_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_new_device_provisioning_repository__assigned_hub_id;
DROP INDEX IF EXISTS public.idx_new_device_provisioning_repository__device_classification;
DROP INDEX IF EXISTS public.idx_new_device_provisioning_repository__management_ip;
DROP INDEX IF EXISTS public.idx_new_device_provisioning_repository__management_gateway;
DROP INDEX IF EXISTS public.idx_new_device_provisioning_repository__datetimestamp;

-- Table
DROP TABLE IF EXISTS public.new_device_provisioning_repository CASCADE;

-- ============================================================
-- Table: public.mac_address_table
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.mac_address_table DROP CONSTRAINT IF EXISTS "mac_address_table__cIndex_unique__uq";
ALTER TABLE IF EXISTS public.mac_address_table DROP CONSTRAINT IF EXISTS mac_address_table_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_mac_address_table__interface_description;

-- Table
DROP TABLE IF EXISTS public.mac_address_table CASCADE;

-- ============================================================
-- Table: public.ipv4_exclude_from_discovery_scans
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.ipv4_exclude_from_discovery_scans DROP CONSTRAINT IF EXISTS ipv4_exclude_from_discovery_scans__pk;
ALTER TABLE IF EXISTS public.ipv4_exclude_from_discovery_scans DROP CONSTRAINT IF EXISTS ipv4_exclude_from_discovery_scans_pkey;

-- Table
DROP TABLE IF EXISTS public.ipv4_exclude_from_discovery_scans CASCADE;

-- ============================================================
-- Table: public.hub_id_list_archive
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.hub_id_list_archive DROP CONSTRAINT IF EXISTS hub_id_list_archive__pk;
ALTER TABLE IF EXISTS public.hub_id_list_archive DROP CONSTRAINT IF EXISTS hub_id_list_archive_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_hub_id_list_archive__hub_id;
DROP INDEX IF EXISTS public.idx_hub_id_list_archive__device_name;

-- Table
DROP TABLE IF EXISTS public.hub_id_list_archive CASCADE;

-- ============================================================
-- Table: public.hub_id_list
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.hub_id_list DROP CONSTRAINT IF EXISTS hub_id_list__pk;
ALTER TABLE IF EXISTS public.hub_id_list DROP CONSTRAINT IF EXISTS hub_id_list__hub_id__uq;
ALTER TABLE IF EXISTS public.hub_id_list DROP CONSTRAINT IF EXISTS hub_id_list__device_name__uq;
ALTER TABLE IF EXISTS public.hub_id_list DROP CONSTRAINT IF EXISTS hub_id_list_pkey;

-- Table
DROP TABLE IF EXISTS public.hub_id_list CASCADE;

-- ============================================================
-- Table: public.hardware_inventory_on_hand_history
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.hardware_inventory_on_hand_history DROP CONSTRAINT IF EXISTS hardware_inventory_on_hand_history__pk;
ALTER TABLE IF EXISTS public.hardware_inventory_on_hand_history DROP CONSTRAINT IF EXISTS hardware_inventory_on_hand_history_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__location;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__vendor;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__type;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__model_number;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__part_number;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__serial_number;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__purchase_date;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__purchase_order_number;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__funding_source;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__in_use_flag;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__in_use_auto_di_3468332e;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__found_in_device_name;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__rma_flag;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__rma_date;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__rma_ship_to;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__rma_tracking_number;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__spare_flag;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__recycled_flag;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__order_date;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__datetimestamp;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__functional_area;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__room_number;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__ethernet_address;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand_history__assigned_subnet_number;

-- Table
DROP TABLE IF EXISTS public.hardware_inventory_on_hand_history CASCADE;

-- ============================================================
-- Table: public.hardware_inventory_on_hand
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.hardware_inventory_on_hand DROP CONSTRAINT IF EXISTS hardware_inventory_on_hand__pk;
ALTER TABLE IF EXISTS public.hardware_inventory_on_hand DROP CONSTRAINT IF EXISTS hardware_inventory_on_hand__serial_number__uq;
ALTER TABLE IF EXISTS public.hardware_inventory_on_hand DROP CONSTRAINT IF EXISTS hardware_inventory_on_hand_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__id;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__location;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__vendor;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__type;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__purchase_date;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__purchase_order_number;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__funding_source;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__in_use_flag;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__in_use_auto_discover_date;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__found_in_device_name;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__rma_flag;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__rma_date;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__rma_ship_to;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__rma_tracking_number;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__spare_flag;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__recycled_flag;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__order_date;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__datetimestamp;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__functional_area;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__room_number;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__ethernet_address;
DROP INDEX IF EXISTS public.idx_hardware_inventory_on_hand__assigned_subnet_number;

-- Table
DROP TABLE IF EXISTS public.hardware_inventory_on_hand CASCADE;

-- ============================================================
-- Table: public.hardware_inventory_history
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.hardware_inventory_history DROP CONSTRAINT IF EXISTS hardware_inventory_history__pk;
ALTER TABLE IF EXISTS public.hardware_inventory_history DROP CONSTRAINT IF EXISTS hardware_inventory_history_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_hardware_inventory_history__device_name;
DROP INDEX IF EXISTS public.idx_hardware_inventory_history__chassis_model;
DROP INDEX IF EXISTS public.idx_hardware_inventory_history__ipv4_loopback;
DROP INDEX IF EXISTS public.idx_hardware_inventory_history__ipv6_loopback;
DROP INDEX IF EXISTS public.idx_hardware_inventory_history__device_type;
DROP INDEX IF EXISTS public.idx_hardware_inventory_history__serial_number;
DROP INDEX IF EXISTS public.idx_hardware_inventory_history__model_name;

-- Table
DROP TABLE IF EXISTS public.hardware_inventory_history CASCADE;

-- ============================================================
-- Table: public.hardware_inventory
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.hardware_inventory DROP CONSTRAINT IF EXISTS hardware_inventory__pk;
ALTER TABLE IF EXISTS public.hardware_inventory DROP CONSTRAINT IF EXISTS hardware_inventory_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_hardware_inventory__device_name;
DROP INDEX IF EXISTS public.idx_hardware_inventory__chassis_model;
DROP INDEX IF EXISTS public.idx_hardware_inventory__ipv4_loopback;
DROP INDEX IF EXISTS public.idx_hardware_inventory__ipv6_loopback;
DROP INDEX IF EXISTS public.idx_hardware_inventory__device_type;
DROP INDEX IF EXISTS public.idx_hardware_inventory__serial_number;
DROP INDEX IF EXISTS public.idx_hardware_inventory__model_name;

-- Table
DROP TABLE IF EXISTS public.hardware_inventory CASCADE;

-- ============================================================
-- Table: public.global_vlan_database
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.global_vlan_database DROP CONSTRAINT IF EXISTS global_vlan_database__pk;
ALTER TABLE IF EXISTS public.global_vlan_database DROP CONSTRAINT IF EXISTS global_vlan_database__vlan_id__uq;
ALTER TABLE IF EXISTS public.global_vlan_database DROP CONSTRAINT IF EXISTS global_vlan_database_pkey;

-- Table
DROP TABLE IF EXISTS public.global_vlan_database CASCADE;

-- ============================================================
-- Table: public.discovery_jobs_history
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.discovery_jobs_history DROP CONSTRAINT IF EXISTS discovery_jobs_history__pk;
ALTER TABLE IF EXISTS public.discovery_jobs_history DROP CONSTRAINT IF EXISTS discovery_jobs_history_pkey;

-- Table
DROP TABLE IF EXISTS public.discovery_jobs_history CASCADE;

-- ============================================================
-- Table: public.discovery_jobs_active
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.discovery_jobs_active DROP CONSTRAINT IF EXISTS discovery_jobs_active__pk;
ALTER TABLE IF EXISTS public.discovery_jobs_active DROP CONSTRAINT IF EXISTS discovery_jobs_active__ipv4_address__uq;
ALTER TABLE IF EXISTS public.discovery_jobs_active DROP CONSTRAINT IF EXISTS discovery_jobs_active_pkey;

-- Table
DROP TABLE IF EXISTS public.discovery_jobs_active CASCADE;

-- ============================================================
-- Table: public.devices_no_profile
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.devices_no_profile DROP CONSTRAINT IF EXISTS devices_no_profile__pk;
ALTER TABLE IF EXISTS public.devices_no_profile DROP CONSTRAINT IF EXISTS devices_no_profile_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_devices_no_profile__device_name;
DROP INDEX IF EXISTS public.idx_devices_no_profile__ipv4_loopback;
DROP INDEX IF EXISTS public.idx_devices_no_profile__ipv6_loopback;
DROP INDEX IF EXISTS public.idx_devices_no_profile__device_type;
DROP INDEX IF EXISTS public.idx_devices_no_profile__chassis_model;
DROP INDEX IF EXISTS public.idx_devices_no_profile__os;
DROP INDEX IF EXISTS public.idx_devices_no_profile__version;

-- Table
DROP TABLE IF EXISTS public.devices_no_profile CASCADE;

-- ============================================================
-- Table: public.devices_archive
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.devices_archive DROP CONSTRAINT IF EXISTS devices_archive__pk;
ALTER TABLE IF EXISTS public.devices_archive DROP CONSTRAINT IF EXISTS devices_archive_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_devices_archive__device_name;
DROP INDEX IF EXISTS public.idx_devices_archive__ipv4_loopback;
DROP INDEX IF EXISTS public.idx_devices_archive__ipv6_loopback;
DROP INDEX IF EXISTS public.idx_devices_archive__device_type;
DROP INDEX IF EXISTS public.idx_devices_archive__chassis_model;
DROP INDEX IF EXISTS public.idx_devices_archive__os;
DROP INDEX IF EXISTS public.idx_devices_archive__version;

-- Table
DROP TABLE IF EXISTS public.devices_archive CASCADE;

-- ============================================================
-- Table: public.devices
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.devices DROP CONSTRAINT IF EXISTS devices__pk;
ALTER TABLE IF EXISTS public.devices DROP CONSTRAINT IF EXISTS devices__device_name__uq;
ALTER TABLE IF EXISTS public.devices DROP CONSTRAINT IF EXISTS devices__ipv4_loopback__uq;
ALTER TABLE IF EXISTS public.devices DROP CONSTRAINT IF EXISTS devices_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_devices__ipv6_loopback;
DROP INDEX IF EXISTS public.idx_devices__device_type;
DROP INDEX IF EXISTS public.idx_devices__chassis_model;
DROP INDEX IF EXISTS public.idx_devices__os;
DROP INDEX IF EXISTS public.idx_devices__version;
DROP INDEX IF EXISTS public.idx_devices__site_abbreviation;
DROP INDEX IF EXISTS public.idx_devices__hub_id;

-- Table
DROP TABLE IF EXISTS public.devices CASCADE;

-- ============================================================
-- Table: public.device_reachability_unreachable
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.device_reachability_unreachable DROP CONSTRAINT IF EXISTS device_reachability_unreachable__pk;
ALTER TABLE IF EXISTS public.device_reachability_unreachable DROP CONSTRAINT IF EXISTS device_reachability_unreachable__ipv4_address__uq;
ALTER TABLE IF EXISTS public.device_reachability_unreachable DROP CONSTRAINT IF EXISTS device_reachability_unreachable_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_device_reachability_unreachable__protocol;
DROP INDEX IF EXISTS public.idx_device_reachability_unreachable__status;

-- Table
DROP TABLE IF EXISTS public.device_reachability_unreachable CASCADE;

-- ============================================================
-- Table: public.device_reachability
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.device_reachability DROP CONSTRAINT IF EXISTS device_reachability__pk;
ALTER TABLE IF EXISTS public.device_reachability DROP CONSTRAINT IF EXISTS device_reachability__ipv4_address__uq;
ALTER TABLE IF EXISTS public.device_reachability DROP CONSTRAINT IF EXISTS device_reachability_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_device_reachability__protocol;
DROP INDEX IF EXISTS public.idx_device_reachability__status;

-- Table
DROP TABLE IF EXISTS public.device_reachability CASCADE;

-- ============================================================
-- Table: public.device_profile_production
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.device_profile_production DROP CONSTRAINT IF EXISTS device_profile_production__pk;
ALTER TABLE IF EXISTS public.device_profile_production DROP CONSTRAINT IF EXISTS device_profile_production__model__uq;
ALTER TABLE IF EXISTS public.device_profile_production DROP CONSTRAINT IF EXISTS device_profile_production_pkey;

-- Table
DROP TABLE IF EXISTS public.device_profile_production CASCADE;

-- ============================================================
-- Table: public.device_profile_history
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.device_profile_history DROP CONSTRAINT IF EXISTS device_profile_history__pk;
ALTER TABLE IF EXISTS public.device_profile_history DROP CONSTRAINT IF EXISTS device_profile_history_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_device_profile_history__model_number;

-- Table
DROP TABLE IF EXISTS public.device_profile_history CASCADE;

-- ============================================================
-- Table: public.device_profile_development
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.device_profile_development DROP CONSTRAINT IF EXISTS device_profile_development__pk;
ALTER TABLE IF EXISTS public.device_profile_development DROP CONSTRAINT IF EXISTS device_profile_development__model__uq;
ALTER TABLE IF EXISTS public.device_profile_development DROP CONSTRAINT IF EXISTS device_profile_development_pkey;

-- Table
DROP TABLE IF EXISTS public.device_profile_development CASCADE;

-- ============================================================
-- Table: public.device_backup_que
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.device_backup_que DROP CONSTRAINT IF EXISTS device_backup_que__pk;
ALTER TABLE IF EXISTS public.device_backup_que DROP CONSTRAINT IF EXISTS "device_backup_que__UQ_ipv4_loopback__uq";
ALTER TABLE IF EXISTS public.device_backup_que DROP CONSTRAINT IF EXISTS device_backup_que_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_device_backup_que__device_name;
DROP INDEX IF EXISTS public.idx_device_backup_que__ipv6_loopback;
DROP INDEX IF EXISTS public.idx_device_backup_que__device_type;

-- Table
DROP TABLE IF EXISTS public.device_backup_que CASCADE;

-- ============================================================
-- Table: public.device_backup_locations
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.device_backup_locations DROP CONSTRAINT IF EXISTS device_backup_locations__pk;
ALTER TABLE IF EXISTS public.device_backup_locations DROP CONSTRAINT IF EXISTS device_backup_locations_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_device_backup_locations__device_name;
DROP INDEX IF EXISTS public.idx_device_backup_locations__ipv4_loopback;
DROP INDEX IF EXISTS public.idx_device_backup_locations__ipv6_loopback;
DROP INDEX IF EXISTS public.idx_device_backup_locations__device_type;
DROP INDEX IF EXISTS public.idx_device_backup_locations__datetimestamp;

-- Table
DROP TABLE IF EXISTS public.device_backup_locations CASCADE;

-- ============================================================
-- Table: public.department_names
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.department_names DROP CONSTRAINT IF EXISTS department_names__pk;
ALTER TABLE IF EXISTS public.department_names DROP CONSTRAINT IF EXISTS department_names_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_department_names__department_name;

-- Table
DROP TABLE IF EXISTS public.department_names CASCADE;

-- ============================================================
-- Table: public.deleted_device_provisioning_repository
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.deleted_device_provisioning_repository DROP CONSTRAINT IF EXISTS deleted_device_provisioning_repository__pk;
ALTER TABLE IF EXISTS public.deleted_device_provisioning_repository DROP CONSTRAINT IF EXISTS deleted_device_provisioning_repository__device_host_name__uq;
ALTER TABLE IF EXISTS public.deleted_device_provisioning_repository DROP CONSTRAINT IF EXISTS deleted_device_provisioning_repository_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_deleted_device_provisioning_repository__assigned_hub_id;
DROP INDEX IF EXISTS public.idx_deleted_device_provisioning_repository__device_cla_fea81ee5;
DROP INDEX IF EXISTS public.idx_deleted_device_provisioning_repository__management_ip;
DROP INDEX IF EXISTS public.idx_deleted_device_provisioning_repository__management_gateway;
DROP INDEX IF EXISTS public.idx_deleted_device_provisioning_repository__datetimestamp;

-- Table
DROP TABLE IF EXISTS public.deleted_device_provisioning_repository CASCADE;

-- ============================================================
-- Table: public.circuits
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.circuits DROP CONSTRAINT IF EXISTS circuits__pk;
ALTER TABLE IF EXISTS public.circuits DROP CONSTRAINT IF EXISTS circuits__circuit_number_uniq__uq;
ALTER TABLE IF EXISTS public.circuits DROP CONSTRAINT IF EXISTS circuits__full_circuit_id_uniq__uq;
ALTER TABLE IF EXISTS public.circuits DROP CONSTRAINT IF EXISTS circuits_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_circuits__circuit_id;
DROP INDEX IF EXISTS public.idx_circuits__status;
DROP INDEX IF EXISTS public.idx_circuits__circuit_type;
DROP INDEX IF EXISTS public.idx_circuits__originating_hub_id;
DROP INDEX IF EXISTS public.idx_circuits__originating_hub_interface;
DROP INDEX IF EXISTS public.idx_circuits__terminating_station_cable;
DROP INDEX IF EXISTS public.idx_circuits__terminating_station_pair;
DROP INDEX IF EXISTS public.idx_circuits__requester;
DROP INDEX IF EXISTS public.idx_circuits__new_request_id;

-- Table
DROP TABLE IF EXISTS public.circuits CASCADE;

-- ============================================================
-- Table: public.circuit_types
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.circuit_types DROP CONSTRAINT IF EXISTS circuit_types__pk;
ALTER TABLE IF EXISTS public.circuit_types DROP CONSTRAINT IF EXISTS circuit_types__circuit_type_uniq__uq;
ALTER TABLE IF EXISTS public.circuit_types DROP CONSTRAINT IF EXISTS circuit_types_pkey;

-- Table
DROP TABLE IF EXISTS public.circuit_types CASCADE;

-- ============================================================
-- Table: public.circuit_number_status
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.circuit_number_status DROP CONSTRAINT IF EXISTS circuit_number_status__pk;
ALTER TABLE IF EXISTS public.circuit_number_status DROP CONSTRAINT IF EXISTS circuit_number_status_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_circuit_number_status__status;

-- Table
DROP TABLE IF EXISTS public.circuit_number_status CASCADE;

-- ============================================================
-- Table: public.circuit_id
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.circuit_id DROP CONSTRAINT IF EXISTS circuit_id__pk;
ALTER TABLE IF EXISTS public.circuit_id DROP CONSTRAINT IF EXISTS circuit_id_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_circuit_id__type;

-- Table
DROP TABLE IF EXISTS public.circuit_id CASCADE;

-- ============================================================
-- Table: public.archived_device_provisioning_repository
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.archived_device_provisioning_repository DROP CONSTRAINT IF EXISTS archived_device_provisioning_repository__pk;
ALTER TABLE IF EXISTS public.archived_device_provisioning_repository DROP CONSTRAINT IF EXISTS archived_device_provisioning_repository_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_archived_device_provisioning_repository__device_host_name;
DROP INDEX IF EXISTS public.idx_archived_device_provisioning_repository__assigned_hub_id;
DROP INDEX IF EXISTS public.idx_archived_device_provisioning_repository__device_cl_e77e97bc;
DROP INDEX IF EXISTS public.idx_archived_device_provisioning_repository__management_ip;
DROP INDEX IF EXISTS public.idx_archived_device_provisioning_repository__management_gateway;
DROP INDEX IF EXISTS public.idx_archived_device_provisioning_repository__datetimestamp;

-- Table
DROP TABLE IF EXISTS public.archived_device_provisioning_repository CASCADE;

-- ============================================================
-- Table: public.app_frontend_tracking
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.app_frontend_tracking DROP CONSTRAINT IF EXISTS app_frontend_tracking__pk;
ALTER TABLE IF EXISTS public.app_frontend_tracking DROP CONSTRAINT IF EXISTS app_frontend_tracking_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_app_frontend_tracking__username;
DROP INDEX IF EXISTS public.idx_app_frontend_tracking__route;
DROP INDEX IF EXISTS public.idx_app_frontend_tracking__datetimestamp;

-- Table
DROP TABLE IF EXISTS public.app_frontend_tracking CASCADE;

-- ============================================================
-- Table: public.app_backend_tracking
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.app_backend_tracking DROP CONSTRAINT IF EXISTS app_backend_tracking__pk;
ALTER TABLE IF EXISTS public.app_backend_tracking DROP CONSTRAINT IF EXISTS app_backend_tracking_pkey;

-- Indexes
DROP INDEX IF EXISTS public.idx_app_backend_tracking__datetimestamp;
DROP INDEX IF EXISTS public.idx_app_backend_tracking__route;

-- Table
DROP TABLE IF EXISTS public.app_backend_tracking CASCADE;


-- ============================================================
-- Table: public.app_tracking_celery
-- ============================================================
-- Constraints (drop first to avoid 'index required by constraint' errors)
ALTER TABLE IF EXISTS public.app_tracking_celery DROP CONSTRAINT IF EXISTS app_tracking_celery_parent_job_id_fkey;
ALTER TABLE IF EXISTS public.app_tracking_celery DROP CONSTRAINT IF EXISTS app_tracking_celery__pk;
ALTER TABLE IF EXISTS public.app_tracking_celery DROP CONSTRAINT IF EXISTS app_tracking_celery_pkey;
ALTER TABLE IF EXISTS public.app_tracking_celery DROP CONSTRAINT IF EXISTS app_tracking_celery__status__chk;

-- Indexes
DROP INDEX IF EXISTS public.app_tracking_celery__uidx_task_id;
DROP INDEX IF EXISTS public.app_tracking_celery__idx_status_created_at;
DROP INDEX IF EXISTS public.app_tracking_celery__idx_completed_at;
DROP INDEX IF EXISTS public.app_tracking_celery__idx_correlation_id;
DROP INDEX IF EXISTS public.app_tracking_celery__idx_job_name_created_at;
DROP INDEX IF EXISTS public.app_tracking_celery__idx_active_jobs;
DROP INDEX IF EXISTS public.app_tracking_celery__gin_request;

-- Table
DROP TABLE IF EXISTS public.app_tracking_celery CASCADE;

-- Function (used by the updated_at trigger)
DROP FUNCTION IF EXISTS public.trg_set_updated_at();

COMMIT;
