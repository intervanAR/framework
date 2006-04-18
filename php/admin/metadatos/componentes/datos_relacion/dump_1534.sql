------------------------------------------------------------
--[1534]--  OBJETO - EI formulario 
------------------------------------------------------------
INSERT INTO apex_objeto (proyecto, objeto, anterior, reflexivo, clase_proyecto, clase, subclase, subclase_archivo, objeto_categoria_proyecto, objeto_categoria, nombre, titulo, colapsable, descripcion, fuente_datos_proyecto, fuente_datos, solicitud_registrar, solicitud_obj_obs_tipo, solicitud_obj_observacion, parametro_a, parametro_b, parametro_c, parametro_d, parametro_e, parametro_f, usuario, creacion) VALUES ('toba', '1534', NULL, NULL, 'toba', 'objeto_datos_relacion', NULL, NULL, NULL, NULL, 'OBJETO - EI formulario', NULL, NULL, NULL, 'toba', 'instancia', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2005-08-28 03:48:45');
INSERT INTO apex_objeto_datos_rel (proyecto, objeto, debug, clave, ap, ap_clase, ap_archivo, sinc_susp_constraints, sinc_orden_automatico) VALUES ('toba', '1534', '0', NULL, '3', 'ap_relacion_objeto', 'admin/db/ap_relacion_objeto.php', '0', '1');
INSERT INTO apex_objeto_datos_rel_asoc (proyecto, objeto, asoc_id, identificador, padre_proyecto, padre_objeto, padre_id, padre_clave, hijo_proyecto, hijo_objeto, hijo_id, hijo_clave, cascada, orden) VALUES ('toba', '1534', '10', 'base -> efs', 'toba', '1529', 'prop_basicas', 'objeto_ut_formulario_proyecto,objeto_ut_formulario', 'toba', '1530', 'efs', 'objeto_ei_formulario_proyecto,objeto_ei_formulario', '0', '2');
INSERT INTO apex_objeto_datos_rel_asoc (proyecto, objeto, asoc_id, identificador, padre_proyecto, padre_objeto, padre_id, padre_clave, hijo_proyecto, hijo_objeto, hijo_id, hijo_clave, cascada, orden) VALUES ('toba', '1534', '11', 'base -> eventos', 'toba', '1501', 'base', 'proyecto,objeto', 'toba', '1505', 'eventos', 'proyecto,objeto', '0', '3');
INSERT INTO apex_objeto_datos_rel_asoc (proyecto, objeto, asoc_id, identificador, padre_proyecto, padre_objeto, padre_id, padre_clave, hijo_proyecto, hijo_objeto, hijo_id, hijo_clave, cascada, orden) VALUES ('toba', '1534', '18', 'base -> prop_basicas', 'toba', '1501', 'base', 'proyecto,objeto', 'toba', '1529', 'prop_basicas', 'objeto_ut_formulario_proyecto,objeto_ut_formulario', '0', '1');
INSERT INTO apex_objeto_dependencias (proyecto, dep_id, objeto_consumidor, objeto_proveedor, identificador, parametros_a, parametros_b, parametros_c, inicializar, orden) VALUES ('toba', '106', '1534', '1501', 'base', '1', '1', NULL, NULL, NULL);
INSERT INTO apex_objeto_dependencias (proyecto, dep_id, objeto_consumidor, objeto_proveedor, identificador, parametros_a, parametros_b, parametros_c, inicializar, orden) VALUES ('toba', '107', '1534', '1530', 'efs', '1', '0', NULL, NULL, NULL);
INSERT INTO apex_objeto_dependencias (proyecto, dep_id, objeto_consumidor, objeto_proveedor, identificador, parametros_a, parametros_b, parametros_c, inicializar, orden) VALUES ('toba', '108', '1534', '1505', 'eventos', '0', '0', NULL, NULL, NULL);
INSERT INTO apex_objeto_dependencias (proyecto, dep_id, objeto_consumidor, objeto_proveedor, identificador, parametros_a, parametros_b, parametros_c, inicializar, orden) VALUES ('toba', '109', '1534', '1529', 'prop_basicas', '1', '1', NULL, NULL, NULL);
