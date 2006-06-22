------------------------------------------------------------
--[1000134]--  Clonador de Items - opciones - opciones 
------------------------------------------------------------
INSERT INTO apex_objeto (proyecto, objeto, anterior, reflexivo, clase_proyecto, clase, subclase, subclase_archivo, objeto_categoria_proyecto, objeto_categoria, nombre, titulo, colapsable, descripcion, fuente_datos_proyecto, fuente_datos, solicitud_registrar, solicitud_obj_obs_tipo, solicitud_obj_observacion, parametro_a, parametro_b, parametro_c, parametro_d, parametro_e, parametro_f, usuario, creacion) VALUES ('admin', '1000134', NULL, NULL, 'toba', 'objeto_ei_formulario', 'form_opciones', 'utilitarios/clonador_items/form_opciones.php', NULL, NULL, 'Clonador de Items - opciones - opciones', NULL, '0', NULL, 'admin', 'instancia', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2006-06-17 16:21:32');
INSERT INTO apex_objeto_eventos (proyecto, evento_id, objeto, identificador, etiqueta, maneja_datos, sobre_fila, confirmacion, estilo, imagen_recurso_origen, imagen, en_botonera, ayuda, orden, ci_predep, implicito, display_datos_cargados, grupo, accion, accion_imphtml_debug, accion_vinculo_carpeta, accion_vinculo_item, accion_vinculo_objeto, accion_vinculo_popup, accion_vinculo_popup_param, accion_vinculo_target, accion_vinculo_celda) VALUES ('admin', '1000139', '1000134', 'modificacion', '&Modificacion', '1', NULL, NULL, NULL, NULL, NULL, '0', NULL, '1', NULL, '1', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
INSERT INTO apex_objeto_ut_formulario (objeto_ut_formulario_proyecto, objeto_ut_formulario, tabla, titulo, ev_agregar, ev_agregar_etiq, ev_mod_modificar, ev_mod_modificar_etiq, ev_mod_eliminar, ev_mod_eliminar_etiq, ev_mod_limpiar, ev_mod_limpiar_etiq, ev_mod_clave, clase_proyecto, clase, auto_reset, ancho, ancho_etiqueta, campo_bl, scroll, filas, filas_agregar, filas_agregar_online, filas_undo, filas_ordenar, columna_orden, filas_numerar, ev_seleccion, alto, analisis_cambios) VALUES ('admin', '1000134', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '150px', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
INSERT INTO apex_objeto_ei_formulario_ef (objeto_ei_formulario_proyecto, objeto_ei_formulario, objeto_ei_formulario_fila, identificador, elemento_formulario, columnas, obligatorio, inicializacion, orden, etiqueta, etiqueta_estilo, descripcion, colapsado, desactivado, estilo, total) VALUES ('admin', '1000134', '1000091', 'proyecto', 'ef_combo', 'proyecto', '1', 'dao_:_ get_proyectos_accesibles_;_
clase_:_ dao_editores_;_
include_:_ modelo/consultas/dao_editores.php_;_
clave_:_ proyecto_;_
valor_:_ descripcion_corta_;_', '1', 'Proyecto Destino', NULL, NULL, '0', '0', NULL, '0');
INSERT INTO apex_objeto_ei_formulario_ef (objeto_ei_formulario_proyecto, objeto_ei_formulario, objeto_ei_formulario_fila, identificador, elemento_formulario, columnas, obligatorio, inicializacion, orden, etiqueta, etiqueta_estilo, descripcion, colapsado, desactivado, estilo, total) VALUES ('admin', '1000134', '1000092', 'carpeta', 'ef_combo', 'carpeta', '1', 'dao_:_ get_carpetas_posibles_;_
clase_:_ dao_editores_;_
include_:_ modelo/consultas/dao_editores.php_;_
clave_:_ id_;_
valor_:_ nombre_;_
dependencias_:_ proyecto_;_
no_seteado_:_ --- Seleccione ---_;_', '2', 'Carpeta Destino', NULL, NULL, '0', '0', NULL, '0');
INSERT INTO apex_objeto_ei_formulario_ef (objeto_ei_formulario_proyecto, objeto_ei_formulario, objeto_ei_formulario_fila, identificador, elemento_formulario, columnas, obligatorio, inicializacion, orden, etiqueta, etiqueta_estilo, descripcion, colapsado, desactivado, estilo, total) VALUES ('admin', '1000134', '1000093', 'con_subclases', 'ef_checkbox', 'con_subclases', '0', 'valor_:_ 1_;_
valor_no_seteado_:_ 0_;_
estado_:_ 1_;_', '4', 'Clonar subclases', NULL, NULL, '0', '0', NULL, '0');
INSERT INTO apex_objeto_ei_formulario_ef (objeto_ei_formulario_proyecto, objeto_ei_formulario, objeto_ei_formulario_fila, identificador, elemento_formulario, columnas, obligatorio, inicializacion, orden, etiqueta, etiqueta_estilo, descripcion, colapsado, desactivado, estilo, total) VALUES ('admin', '1000134', '1000094', 'carpeta_subclases', 'ef_editable', 'carpeta_subclases', '0', '', '5', 'Carpeta subclases', NULL, 'Path relativo donde se copiaran las subclases (si existen)', '0', '0', NULL, '0');
INSERT INTO apex_objeto_ei_formulario_ef (objeto_ei_formulario_proyecto, objeto_ei_formulario, objeto_ei_formulario_fila, identificador, elemento_formulario, columnas, obligatorio, inicializacion, orden, etiqueta, etiqueta_estilo, descripcion, colapsado, desactivado, estilo, total) VALUES ('admin', '1000134', '1000106', 'anexo', 'ef_editable', 'anexo', '0', '', '3', 'Anexo Nombre', NULL, 'Modifica el nombre del item y sus componentes agregando una cadena al inicio de cada nombre.', '0', '0', NULL, '0');
