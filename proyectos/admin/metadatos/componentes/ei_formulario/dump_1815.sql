------------------------------------------------------------
--[1815]--  Usuario - Proyecto 
------------------------------------------------------------
INSERT INTO apex_objeto (proyecto, objeto, anterior, reflexivo, clase_proyecto, clase, subclase, subclase_archivo, objeto_categoria_proyecto, objeto_categoria, nombre, titulo, colapsable, descripcion, fuente_datos_proyecto, fuente_datos, solicitud_registrar, solicitud_obj_obs_tipo, solicitud_obj_observacion, parametro_a, parametro_b, parametro_c, parametro_d, parametro_e, parametro_f, usuario, creacion) VALUES ('admin', '1815', NULL, NULL, 'toba', 'objeto_ei_formulario', NULL, NULL, NULL, NULL, 'Usuario - Proyecto', 'Propiedades dentro de este proyecto', NULL, NULL, 'admin', 'instancia', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2006-02-17 04:43:45');
INSERT INTO apex_objeto_eventos (proyecto, evento_id, objeto, identificador, etiqueta, maneja_datos, sobre_fila, confirmacion, estilo, imagen_recurso_origen, imagen, en_botonera, ayuda, orden, ci_predep, implicito, display_datos_cargados, grupo, accion, accion_imphtml_debug, accion_vinculo_carpeta, accion_vinculo_item, accion_vinculo_objeto, accion_vinculo_popup, accion_vinculo_popup_param, accion_vinculo_target, accion_vinculo_celda) VALUES ('admin', '421', '1815', 'modificacion', '&Modificacion', '1', NULL, NULL, NULL, NULL, NULL, '0', NULL, '1', NULL, '1', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
INSERT INTO apex_objeto_ut_formulario (objeto_ut_formulario_proyecto, objeto_ut_formulario, tabla, titulo, ev_agregar, ev_agregar_etiq, ev_mod_modificar, ev_mod_modificar_etiq, ev_mod_eliminar, ev_mod_eliminar_etiq, ev_mod_limpiar, ev_mod_limpiar_etiq, ev_mod_clave, clase_proyecto, clase, auto_reset, ancho, ancho_etiqueta, campo_bl, scroll, filas, filas_agregar, filas_agregar_online, filas_undo, filas_ordenar, columna_orden, filas_numerar, ev_seleccion, alto, analisis_cambios) VALUES ('admin', '1815', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '150px', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
INSERT INTO apex_objeto_ei_formulario_ef (objeto_ei_formulario_proyecto, objeto_ei_formulario, objeto_ei_formulario_fila, identificador, elemento_formulario, columnas, obligatorio, inicializacion, orden, etiqueta, etiqueta_estilo, descripcion, colapsado, desactivado, estilo, total) VALUES ('admin', '1815', '4572', 'usuario_grupo_acc', 'ef_combo', 'usuario_grupo_acc', '1', 'dao_:_ get_grupos_acceso_;_
clase_:_ dao_permisos_;_
include_:_ modelo/consultas/dao_permisos.php_;_
clave_:_ usuario_grupo_acc_;_
valor_:_ nombre_;_
no_seteado_:_ --Seleccione--_;_
', '1', 'Grupo Acceso', NULL, NULL, NULL, NULL, NULL, '0');
INSERT INTO apex_objeto_ei_formulario_ef (objeto_ei_formulario_proyecto, objeto_ei_formulario, objeto_ei_formulario_fila, identificador, elemento_formulario, columnas, obligatorio, inicializacion, orden, etiqueta, etiqueta_estilo, descripcion, colapsado, desactivado, estilo, total) VALUES ('admin', '1815', '4573', 'usuario_perfil_datos', 'ef_combo', 'usuario_perfil_datos', '1', 'dao_:_ get_perfiles_datos_;_
clase_:_ dao_permisos_;_
include_:_ modelo/consultas/dao_permisos.php_;_
clave_:_ usuario_perfil_datos_;_
valor_:_ nombre_;_
', '2', 'Perfil de Datos', NULL, NULL, NULL, NULL, NULL, '0');
