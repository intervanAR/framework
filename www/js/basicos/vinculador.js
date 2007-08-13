
var vinculador;

/**
 * @class Permite construir URLs para navegar hacia items del proyecto pasando parámetros específicos
 * @constructor
 * @phpdoc Centrales/toba_vinculador toba::vinculador()
 */
vinculador = new function() {
	this._vinculos = [];	
};
	/**
	 * Crea una URL hacia la operación actual
	 * @param {string} servicio Servicio a solicitar (opcional) por defecto generar_html
	 * @param {Object} parametros Objeto asociativo parametro=>valor (ej. {'precio': 123} )
	 * @param {Array} objetos Ids. de componentes destino del servicio (opcional)
	 * @type String
	 */
	vinculador.crear_autovinculo = function(servicio, parametros, objetos) {
		return this.crear(toba_hilo_item, servicio, parametros, objetos);
	};

	/**
	 * Crea una URL hacia un item especifico
	 * @param {string} destino Item destino
	 * @param {string} servicio Servicio a solicitar (opcional) por defecto generar_html
	 * @param {Object} parametros Objeto asociativo parametro=>valor (ej. {'precio': 123} )
	 * @param {Array} objetos Ids. de componentes destino del servicio (opcional)
	 * @type String
	 */	
	vinculador.crear = function(destino, servicio, parametros, objetos) {
		var vinc = toba_prefijo_vinculo + "&" + toba_hilo_qs + "=" + destino[0] + toba_hilo_separador + destino[1];
		if (typeof servicio != 'undefined') {
			vinc += '&' + toba_hilo_qs_servicio + "=" + servicio;
		}
		if (typeof parametros != 'undefined') {
			vinc = this.concatenar_parametros_url(vinc, parametros);
		}
		if (typeof objetos != 'undefined') {
			vinc += '&' + toba_hilo_qs_objetos_destino + "=";
			for (var i=0; i<objetos.length; i++) {
				vinc += objetos[i][0] + toba_hilo_separador + objetos[i][1] + ',';
			}
		}
		return vinc;
	};
	
	/**
	 * Toma una URL y le agrega parametros
	 * @param {String} vinculo URL original
	 * @param {Object} parametros Objeto asociativo parametro=>valor (ej. {'precio': 123} )
	 * @type String
	 */
	vinculador.concatenar_parametros_url = function(vinculo, parametros) {
		for (var i in parametros) {
			vinculo += '&' + i + '=' + encodeURI(parametros[i]);
		}
		return vinculo;
	};
	
	/**
	 * Navega hacia otro proyecto
	 * @param {string} proyecto Id. del proyecto destino
	 */
	vinculador.ir_a_proyecto = function(proyecto) {
		window.location.href = window.url_proyectos[proyecto];
	};

	//--------------------------------------------------
	// Manejo de vinculos registrados en PHP
	//--------------------------------------------------
	
	/**
	 * Invoca un vinculo registrado en PHP
	 * @param {string} identificador Id. del vinculo previamente generado
	 */
	vinculador.invocar = function(identificador) {
		if (typeof this._vinculos[identificador] == 'undefined') {
		 	notificacion.agregar('Ud. no tiene permisos para ingresar a esta operación');
		 	notificacion.mostrar();
		 	return;
		}
		if (this._vinculos[identificador].activado != 1) { return; }	//Desactivado
		if (typeof this._vinculos[identificador].parametros == 'undefined') {
			url = this._vinculos[identificador].url;
		} else {
			url = this.concatenar_parametros_url( 	this._vinculos[identificador].url,
													this._vinculos[identificador].parametros );
		}
		if (this._vinculos[identificador].popup == '1' ) {
			abrir_popup(identificador,url,this._vinculos[identificador].popup_parametros);
		} else {
			if( this._vinculos[identificador].target !== '' ) {
				idtarget = this._vinculos[identificador].target;
				window.parent.frames[idtarget].document.location.href = url;
			} else {
				document.location.href = url;
			}
		}
	};

	/**
	 * Toma un vinculo registrado en PHP y le agrega parametros
	 * @param {string} identificador Id. del vinculo previamente generado
	 * @param {Object} parametros Objeto asociativo parametro=>valor (ej. {'precio': 123} )	 
	 */	
	vinculador.agregar_parametros = function(identificador, parametros) {
		if (typeof this._vinculos[identificador] == 'undefined') {return;}
		if (typeof this._vinculos[identificador].parametros == 'undefined') {
			this._vinculos[identificador].parametros= parametros;
		} else {
			for (var i in parametros) {
				this._vinculos[identificador].parametros[i] = parametros[i];
			}	
		}
	};

	/**
	 * Desactiva un vinculo registrado en PHP. De esta forma no se va a invocar
	 * @param {string} identificador Id. del vinculo previamente generado
	 */	
	vinculador.desactivar_vinculo = function(identificador) {
		if (typeof this._vinculos[identificador] == 'undefined' ) {return;}
		this._vinculos[identificador].activado = 0;
	};

	/**
	 * Activa un vinculo registrado en PHP previamente desactivado
	 * @param {string} identificador Id. del vinculo previamente generado
	 */		
	vinculador.activar_vinculo = function(identificador) {
		if (typeof this._vinculos[identificador] == 'undefined' ) {return;}
		this._vinculos[identificador].activado = 1;
	};
	
	/** 
	 * Registra un nuevo vinculo
	 * A travez de este metodo el vinculador de PHP habla con el de JS.
	 */
	vinculador.agregar_vinculo = function(identificador, datos) {
		this._vinculos[ identificador ] = datos;
	};

toba.confirmar_inclusion('basicos/vinculador');